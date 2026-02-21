"""
AI Red Team Scanner - Browser Chatbot Interactor
=================================================
Nutzt Playwright um Website-Chatbots automatisch zu finden und zu testen.
Erkennt gängige Chatbot-Widgets und interagiert mit ihnen.

Unterstützte Widgets:
- Leadinfo LeadBot (srcdoc-iframe mit .widget-wrapper)
- Intercom, Drift, Crisp, Tidio, Zendesk, HubSpot
- Custom OpenAI-style Chatbots
- Generische Chat-Widgets
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Gängige Chatbot-Widget-Selektoren
CHATBOT_SELECTORS = {
    "leadinfo": {
        "launcher": '.cta .toggle button, .widget-wrapper .toggle button',
        "input": '.message-container textarea, .message-container input[type="text"]',
        "message": '.message .content, .question .message .content',
        "name": "Leadinfo LeadBot",
    },
    "intercom": {
        "launcher": '[class*="intercom-launcher"]',
        "input": '[class*="intercom"] textarea, [class*="intercom"] input[type="text"]',
        "message": '[class*="intercom-message"]',
        "name": "Intercom",
    },
    "drift": {
        "launcher": '#drift-widget, [class*="drift-"]',
        "input": '[class*="drift"] textarea, [class*="drift"] input',
        "message": '[class*="drift-message"]',
        "name": "Drift",
    },
    "crisp": {
        "launcher": '[class*="crisp-client"]',
        "input": '[class*="crisp"] textarea',
        "message": '[class*="crisp-message"]',
        "name": "Crisp",
    },
    "tidio": {
        "launcher": '#tidio-chat, [class*="tidio"]',
        "input": '[class*="tidio"] textarea, [class*="tidio"] input',
        "message": '[class*="tidio"] [class*="message"]',
        "name": "Tidio",
    },
    "zendesk": {
        "launcher": '[class*="zEWidget"], #launcher',
        "input": '[class*="zEWidget"] textarea',
        "message": '[class*="zEWidget"] [class*="message"]',
        "name": "Zendesk",
    },
    "hubspot": {
        "launcher": '#hubspot-messages-iframe-container',
        "input": '[class*="hubspot"] textarea',
        "message": '[class*="hubspot"] [class*="message"]',
        "name": "HubSpot",
    },
    "custom_openai": {
        "launcher": '[class*="chatgpt"], [class*="openai"], [id*="chat"]',
        "input": 'textarea[placeholder], input[placeholder*="message"], textarea[data-id]',
        "message": '[class*="response"], [class*="answer"], [class*="bot-message"], [class*="assistant"]',
        "name": "Custom (OpenAI-style)",
    },
    "generic": {
        "launcher": '[class*="chat-launcher"], [class*="chat-widget"], [class*="chat-button"], [id*="chat-widget"]',
        "input": 'textarea, input[type="text"][placeholder*="message"], input[type="text"][placeholder*="frag"], input[type="text"][placeholder*="ask"]',
        "message": '[class*="message"], [class*="response"], [class*="reply"], [class*="bot"]',
        "name": "Generic Chat Widget",
    },
}


@dataclass
class ChatMessage:
    """Eine Nachricht im Chat"""
    role: str  # "user" oder "assistant"
    content: str
    timestamp: str = ""


@dataclass
class ChatbotInfo:
    """Informationen über einen erkannten Chatbot"""
    provider: str = "unknown"
    selector_set: dict = field(default_factory=dict)
    iframe_src: Optional[str] = None
    is_iframe: bool = False
    widget_frame: object = None  # Referenz auf den Playwright-Frame des Widgets


class ChatbotInteractor:
    """
    Findet und interagiert mit Chatbots auf Websites.
    Nutzt Playwright für Browser-Automation.
    """

    def __init__(self, browser_config=None):
        self.config = browser_config
        self.browser = None
        self.context = None
        self.page = None
        self.chatbot_info = None
        self._widget_frame = None  # Cache für den aktiven Widget-Frame

    async def setup(self):
        """Browser starten — nutzt Google Chrome statt Chromium"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("Playwright nicht installiert. Bitte: pip install playwright && playwright install")
            raise

        self._playwright = await async_playwright().start()

        engine = getattr(self.config, "browser_engine", "chrome") if self.config else "chrome"
        headless = self.config.headless if self.config else True
        chrome_path = getattr(self.config, "chrome_path", "") if self.config else ""

        # Docker-kompatible Chrome-Flags
        chrome_args = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-default-apps",
            "--disable-sync",
            "--no-first-run",
            "--disable-setuid-sandbox",
        ]

        launch_kwargs = {"headless": headless, "args": chrome_args}

        if engine == "chrome":
            launch_kwargs["channel"] = "chrome"
            logger.info("Verwende Google Chrome (channel='chrome') mit Docker-Flags")
        else:
            logger.info("Verwende Playwright Chromium (Fallback) mit Docker-Flags")

        if chrome_path:
            launch_kwargs["executable_path"] = chrome_path
            logger.info(f"Chrome-Pfad überschrieben: {chrome_path}")

        self.browser = await self._playwright.chromium.launch(**launch_kwargs)

        ua = (self.config.user_agent if self.config else
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        vw = getattr(self.config, "viewport_width", 1280) if self.config else 1280
        vh = getattr(self.config, "viewport_height", 720) if self.config else 720

        self.context = await self.browser.new_context(
            viewport={"width": vw, "height": vh},
            user_agent=ua,
        )
        self.page = await self.context.new_page()
        logger.info(f"Browser gestartet (engine={engine}, headless={headless})")

    async def teardown(self):
        """Browser beenden"""
        if self.browser:
            await self.browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("Browser gestoppt")

    async def navigate_to(self, url: str) -> bool:
        """Zu URL navigieren und Cookie-Banner wegklicken.
        Nutzt domcontentloaded statt networkidle für Docker-Kompatibilität."""
        strategies = [
            ("domcontentloaded", 45000),
            ("load", 60000),
            ("commit", 60000),
        ]

        for wait_until, timeout in strategies:
            try:
                logger.info(f"Navigation zu {url} (wait_until={wait_until}, timeout={timeout}ms)")
                await self.page.goto(url, wait_until=wait_until, timeout=timeout)
                logger.info(f"✅ Navigiert zu: {url} (Strategie: {wait_until})")

                # Extra-Wartezeit für dynamische Inhalte
                await asyncio.sleep(3)

                # Cookie-/Consent-Banner UND Popups wegklicken
                await self._dismiss_overlays()

                await asyncio.sleep(2)
                return True
            except Exception as e:
                logger.warning(f"Navigation mit {wait_until} fehlgeschlagen: {e}")
                continue

        logger.error(f"❌ Navigation zu {url} komplett fehlgeschlagen nach allen Strategien")
        return False

    async def _dismiss_overlays(self):
        """Cookie-Banner, Popups und blockierende Overlays entfernen"""
        # Phase 1: Cookie-Banner mit Buttons
        reject_selectors = [
            'button:has-text("Ablehnen")',
            'button:has-text("Alle ablehnen")',
            'button:has-text("Nur notwendige")',
            'button:has-text("Nur erforderliche")',
            'button:has-text("Nicht akzeptieren")',
            'a:has-text("Ablehnen")',
            'button:has-text("Reject")',
            'button:has-text("Reject all")',
            'button:has-text("Only necessary")',
            'button:has-text("Decline")',
            '[class*="cookie"] button[class*="reject"]',
            '[class*="consent"] button[class*="reject"]',
            '[data-testid*="reject"]',
        ]

        accept_selectors = [
            'button:has-text("Akzeptieren")',
            'button:has-text("Alle akzeptieren")',
            'button:has-text("Zustimmen")',
            'button:has-text("Einverstanden")',
            'button:has-text("OK")',
            'button:has-text("Accept")',
            'button:has-text("Accept all")',
            'button:has-text("I agree")',
            'button:has-text("Got it")',
            '[class*="cookie"] button[class*="accept"]',
            '[class*="consent"] button[class*="accept"]',
        ]

        for sel in reject_selectors:
            try:
                btn = await self.page.query_selector(sel)
                if btn and await btn.is_visible():
                    await btn.click()
                    logger.info(f"Cookie-Banner: 'Ablehnen' geklickt ({sel})")
                    await asyncio.sleep(1)
                    break
            except Exception:
                continue
        else:
            for sel in accept_selectors:
                try:
                    btn = await self.page.query_selector(sel)
                    if btn and await btn.is_visible():
                        await btn.click()
                        logger.info(f"Cookie-Banner: 'Akzeptieren' geklickt ({sel})")
                        await asyncio.sleep(1)
                        break
                except Exception:
                    continue

        # Phase 2: Fullscreen-Overlay-Modals entfernen (z.B. hireka.io Popup)
        try:
            removed = await self.page.evaluate("""
                () => {
                    let removed = 0;
                    // Alle fixed fullscreen overlays entfernen
                    document.querySelectorAll('div').forEach(el => {
                        const style = window.getComputedStyle(el);
                        if (style.position === 'fixed' &&
                            el.offsetWidth > 500 && el.offsetHeight > 500 &&
                            (el.className.includes('inset-0') ||
                             el.className.includes('overlay') ||
                             el.className.includes('modal') ||
                             style.backgroundColor.includes('rgba'))) {
                            // Nicht den Body oder das Chatbot-Widget entfernen
                            if (!el.querySelector('.widget-wrapper') &&
                                !el.querySelector('iframe[srcdoc]')) {
                                el.remove();
                                removed++;
                            }
                        }
                    });
                    document.body.style.overflow = 'auto';
                    return removed;
                }
            """)
            if removed:
                logger.info(f"Overlay-Modals entfernt: {removed}")
        except Exception as e:
            logger.debug(f"Overlay-Entfernung fehlgeschlagen: {e}")

    async def detect_chatbot(self) -> Optional[ChatbotInfo]:
        """Chatbot auf der Seite erkennen — prüft srcdoc-iframes UND direkte Elemente"""
        logger.info("Suche nach Chatbot-Widgets...")

        # Phase 1: srcdoc-iframes durchsuchen (LeadBot, Voiceflow etc.)
        leadbot = await self._detect_srcdoc_chatbot()
        if leadbot:
            return leadbot

        # Phase 2: Bekannte Provider in iframe-URLs suchen
        for frame in self.page.frames:
            frame_url = frame.url.lower()
            for provider, selectors in CHATBOT_SELECTORS.items():
                if provider in frame_url:
                    self.chatbot_info = ChatbotInfo(
                        provider=provider,
                        selector_set=selectors,
                        iframe_src=frame.url,
                        is_iframe=True,
                    )
                    logger.info(f"Chatbot in iframe gefunden: {selectors['name']}")
                    return self.chatbot_info

        # Phase 3: Direkt auf der Seite suchen (ohne generic zuerst)
        for provider, selectors in CHATBOT_SELECTORS.items():
            if provider == "generic":
                continue
            try:
                element = await self.page.query_selector(selectors["launcher"])
                if element:
                    self.chatbot_info = ChatbotInfo(
                        provider=provider,
                        selector_set=selectors,
                    )
                    logger.info(f"Chatbot gefunden: {selectors['name']}")
                    return self.chatbot_info
            except Exception:
                continue

        # Phase 4: Generischer Fallback — nur wenn ein sinnvolles Chat-Element existiert
        try:
            chat_el = await self.page.query_selector(
                '[class*="chat-launcher"], [class*="chat-widget"], '
                '[class*="chat-button"], [id*="chat-widget"]'
            )
            if chat_el:
                self.chatbot_info = ChatbotInfo(
                    provider="generic",
                    selector_set=CHATBOT_SELECTORS["generic"],
                )
                logger.info("Chatbot gefunden: Generic Chat Widget")
                return self.chatbot_info
        except Exception:
            pass

        # Phase 5: KI-Textverarbeitungs-Apps (Textarea + Submit Button)
        form_app = await self._detect_form_app()
        if form_app:
            return form_app

        logger.warning("Kein Chatbot-Widget gefunden")
        return None

    async def _detect_form_app(self) -> Optional[ChatbotInfo]:
        """
        Erkennt KI-Textverarbeitungs-Apps: Textarea + Submit-Button Muster.
        z.B. Hermedix (med. Bericht → Übersetzung), Zusammenfasser, etc.
        """
        try:
            result = await self.page.evaluate("""
                () => {
                    // Suche Textarea
                    const textareas = document.querySelectorAll('textarea');
                    for (const ta of textareas) {
                        const rect = ta.getBoundingClientRect();
                        if (rect.width < 200 || rect.height < 50) continue;

                        // Suche Submit-Button in der Nähe
                        const buttons = document.querySelectorAll('button');
                        for (const btn of buttons) {
                            const text = btn.textContent.trim().toLowerCase();
                            if (text.includes('übersetzen') || text.includes('translate') ||
                                text.includes('analysieren') || text.includes('analyze') ||
                                text.includes('zusammenfass') || text.includes('summarize') ||
                                text.includes('generieren') || text.includes('generate') ||
                                text.includes('submit') || text.includes('senden') ||
                                text.includes('verarbeiten') || text.includes('process') ||
                                text.includes('starten') || text.includes('start') ||
                                text.includes('check') || text.includes('prüfen')) {
                                return {
                                    type: 'form_app',
                                    placeholder: ta.placeholder || '',
                                    buttonText: btn.textContent.trim(),
                                    textareaW: rect.width,
                                    textareaH: rect.height,
                                };
                            }
                        }
                    }
                    return null;
                }
            """)

            if result:
                logger.info(f"KI-Textverarbeitungs-App erkannt: "
                            f"Button='{result.get('buttonText', '?')}', "
                            f"Placeholder='{result.get('placeholder', '')[:60]}'")

                self.chatbot_info = ChatbotInfo(
                    provider="form_app",
                    selector_set={
                        "launcher": "",  # Kein Launcher nötig
                        "input": "textarea",
                        "message": "[class*='result'], [class*='output'], [class*='translation'], "
                                   "[class*='response'], [class*='explanation'], [class*='answer'], "
                                   ".prose, [class*='card']",
                        "submit_button": result.get("buttonText", ""),
                        "name": f"KI-App ({result.get('buttonText', 'Submit')})",
                    },
                )
                # Metadata für send_message
                self._form_app_meta = result
                return self.chatbot_info

        except Exception as e:
            logger.debug(f"Form-App-Erkennung fehlgeschlagen: {e}")

        return None

    async def _detect_srcdoc_chatbot(self) -> Optional[ChatbotInfo]:
        """Erkennt Chatbots die in srcdoc-iframes leben (LeadBot, etc.)"""
        try:
            result = await self.page.evaluate("""
                () => {
                    const iframes = document.querySelectorAll('iframe[srcdoc]');
                    for (const f of iframes) {
                        try {
                            if (!f.contentDocument || !f.contentDocument.body) continue;
                            const html = f.contentDocument.body.innerHTML;

                            // LeadBot (Leadinfo)
                            if (html.includes('widget-wrapper') && html.includes('message-container')) {
                                const hasButtons = f.contentDocument.querySelectorAll('button.reply').length;
                                const hasInput = f.contentDocument.querySelectorAll('textarea, input[type="text"]').length;
                                return {
                                    type: 'leadinfo',
                                    hasButtons: hasButtons,
                                    hasInput: hasInput,
                                    display: f.style.display,
                                    zIndex: f.style.zIndex,
                                };
                            }

                            // Voiceflow
                            if (html.includes('voiceflow') || html.includes('vf-chat')) {
                                return {type: 'voiceflow'};
                            }
                        } catch(e) {}
                    }
                    return null;
                }
            """)

            if result:
                provider = result.get("type", "unknown")
                logger.info(f"srcdoc-Chatbot erkannt: {provider} "
                            f"(buttons={result.get('hasButtons', 0)}, "
                            f"input={result.get('hasInput', 0)}, "
                            f"display={result.get('display', '?')})")

                selectors = CHATBOT_SELECTORS.get(provider, CHATBOT_SELECTORS["leadinfo"])
                self.chatbot_info = ChatbotInfo(
                    provider=provider,
                    selector_set=selectors,
                    is_iframe=True,
                )
                return self.chatbot_info

        except Exception as e:
            logger.debug(f"srcdoc-Erkennung fehlgeschlagen: {e}")

        return None

    async def _activate_widget_iframe(self):
        """
        Macht versteckte Chatbot-iframes sichtbar (display: none → block).
        Kritisch für LeadBot und ähnliche Widgets.
        """
        try:
            activated = await self.page.evaluate("""
                () => {
                    const iframes = document.querySelectorAll('iframe[srcdoc]');
                    let activated = 0;
                    for (const f of iframes) {
                        try {
                            if (!f.contentDocument || !f.contentDocument.body) continue;
                            const html = f.contentDocument.body.innerHTML;
                            if (html.includes('widget-wrapper') || html.includes('chat-widget')) {
                                // Widget-iframe sichtbar machen
                                f.style.setProperty('display', 'block', 'important');
                                f.style.setProperty('height', '700px', 'important');
                                f.style.setProperty('width', '384px', 'important');
                                f.style.setProperty('max-height', '700px', 'important');
                                f.style.setProperty('min-height', '700px', 'important');
                                f.style.setProperty('opacity', '1', 'important');
                                f.style.setProperty('visibility', 'visible', 'important');
                                f.style.setProperty('pointer-events', 'auto', 'important');
                                activated++;
                            }
                        } catch(e) {}
                    }
                    return activated;
                }
            """)
            if activated:
                logger.info(f"Widget-iframe aktiviert: {activated} iframe(s) sichtbar gemacht")
                await asyncio.sleep(1)
                return True
        except Exception as e:
            logger.warning(f"iframe-Aktivierung fehlgeschlagen: {e}")
        return False

    async def _navigate_to_text_input(self):
        """
        Bei button-basierten Bots (LeadBot etc.): Klickt auf den richtigen
        Button um zum Text-Input zu gelangen (z.B. 'Frage & Antwort').

        Trigger-Priorität: Höchste Priorität zuerst, um den richtigen Button zu treffen.
        """
        # Trigger-Keywords nach Priorität sortiert (wichtigste zuerst)
        text_input_triggers = [
            "Frage",       # "Frage & Antwort" — höchste Prio
            "Question",
            "Ask",
            "Chat",
            "Nachricht",
            "Message",
            "Sonstiges",
            "Other",
            "Anderes",
            "Schreiben",
        ]

        for frame in self.page.frames:
            if frame == self.page.main_frame:
                continue
            try:
                buttons = await frame.query_selector_all("button.reply, button[class*='reply']")
                if not buttons:
                    buttons = await frame.query_selector_all(
                        ".replies-box button, [class*='quick-reply'] button"
                    )
                if not buttons:
                    continue

                # Button-Texte sammeln
                btn_texts = []
                for btn in buttons:
                    text = await btn.text_content()
                    btn_texts.append((btn, (text or "").strip()))

                # Trigger-Priorität: Für jeden Trigger (höchste Prio zuerst)
                # alle Buttons prüfen
                for trigger in text_input_triggers:
                    for btn, text in btn_texts:
                        if trigger.lower() in text.lower():
                            logger.info(f"Button-Navigation: Klicke '{text}' (Trigger: '{trigger}')")
                            await btn.click()
                            await asyncio.sleep(3)
                            return True

                # Fallback: Letzten Button klicken (oft der "Sonstiges"-Typ)
                if btn_texts:
                    last_btn, last_text = btn_texts[-1]
                    logger.info(f"Button-Navigation: Kein Trigger, klicke letzten Button: '{last_text}'")
                    await last_btn.click()
                    await asyncio.sleep(3)
                    return True

            except Exception as e:
                logger.debug(f"Button-Navigation in Frame fehlgeschlagen: {e}")

        return False

    async def open_chatbot(self) -> bool:
        """Chatbot-Widget öffnen — mit spezieller Logik für iframe-basierte Widgets"""
        if not self.chatbot_info:
            return False

        # Form-App braucht kein Öffnen — ist bereits sichtbar
        if self.chatbot_info.provider == "form_app":
            logger.info("Form-App: Kein Öffnen nötig, App ist bereits sichtbar")
            return True

        # Phase 1: Blockierende Overlays entfernen
        await self._remove_blocking_overlays()
        await asyncio.sleep(1)

        # Phase 2: Bei iframe-basierten Bots → iframe sichtbar machen
        if self.chatbot_info.is_iframe:
            activated = await self._activate_widget_iframe()
            if activated:
                await asyncio.sleep(2)

                # Phase 3: Bei button-basierten Bots → zum Text-Input navigieren
                navigated = await self._navigate_to_text_input()
                if navigated:
                    # Nochmal warten und prüfen ob ein neuer Dialog/Input erscheint
                    await asyncio.sleep(2)
                    # Rekursiv weitere Buttons navigieren falls nötig
                    await self._navigate_to_text_input()
                    await asyncio.sleep(1)

                logger.info("Chatbot geöffnet (iframe-Aktivierung)")
                return True

        # Phase 4: Standard-Launcher klicken (für nicht-iframe Bots)
        launcher = self.chatbot_info.selector_set.get("launcher", "")
        if not launcher:
            return True

        # Methode 1: Normaler Klick
        try:
            element = await self.page.query_selector(launcher)
            if not element:
                for frame in self.page.frames:
                    try:
                        element = await frame.query_selector(launcher)
                        if element:
                            break
                    except Exception:
                        continue

            if element:
                await element.click(timeout=10000)
                await asyncio.sleep(3)
                logger.info("Chatbot geöffnet (normaler Klick)")
                return True
        except Exception as e:
            logger.warning(f"Normaler Klick fehlgeschlagen: {e}")

        # Methode 2: JavaScript-Klick
        try:
            clicked = await self.page.evaluate(f"""
                () => {{
                    const selectors = {repr(launcher)}.split(', ');
                    for (const sel of selectors) {{
                        const el = document.querySelector(sel);
                        if (el) {{
                            el.click();
                            return true;
                        }}
                    }}
                    return false;
                }}
            """)
            if clicked:
                await asyncio.sleep(3)
                logger.info("Chatbot geöffnet (JavaScript-Klick)")
                return True
        except Exception as e:
            logger.warning(f"JS-Klick fehlgeschlagen: {e}")

        logger.warning("Chatbot-Launcher konnte nicht geklickt werden — versuche trotzdem weiterzumachen")
        return True

    async def _remove_blocking_overlays(self):
        """Entfernt blockierende iframe-Overlays die Pointer-Events abfangen"""
        try:
            removed = await self.page.evaluate("""
                () => {
                    let removed = 0;
                    document.querySelectorAll('iframe[srcdoc]').forEach(iframe => {
                        const rect = iframe.getBoundingClientRect();
                        if (rect.width > 500 && rect.height > 500) {
                            iframe.style.pointerEvents = 'none';
                            removed++;
                        }
                    });
                    document.querySelectorAll('[class*="frame-root"]').forEach(el => {
                        el.style.pointerEvents = 'none';
                        removed++;
                    });
                    return removed;
                }
            """)
            if removed:
                logger.info(f"Blockierende Overlays entschärft: {removed}")
        except Exception as e:
            logger.debug(f"Overlay-Entfernung: {e}")

    async def _get_active_frame(self, max_wait: float = 15.0):
        """
        Findet den richtigen Frame/Context für den Chatbot.
        Wartet bis zu max_wait Sekunden, da Chatbot-iframes nach dem Öffnen
        erst noch geladen werden müssen.
        """
        if self._widget_frame:
            return self._widget_frame

        input_selector = self.chatbot_info.selector_set.get("input", "")

        generic_inputs = [
            'textarea',
            'input[type="text"]',
            'input[placeholder]',
            '[contenteditable="true"]',
            '[role="textbox"]',
        ]
        generic_selector = ", ".join(generic_inputs)

        elapsed = 0
        poll_interval = 1.0

        while elapsed < max_wait:
            # Hauptseite
            if input_selector:
                try:
                    el = await self.page.query_selector(input_selector)
                    if el and await el.is_visible():
                        logger.info("Input-Feld auf Hauptseite gefunden (spezifisch)")
                        self._widget_frame = self.page
                        return self.page
                except Exception:
                    pass

            try:
                el = await self.page.query_selector(generic_selector)
                if el and await el.is_visible():
                    logger.info("Input-Feld auf Hauptseite gefunden (generisch)")
                    self._widget_frame = self.page
                    return self.page
            except Exception:
                pass

            # Alle Frames (inkl. srcdoc-iframes)
            for frame in self.page.frames:
                if frame == self.page.main_frame:
                    continue
                try:
                    if input_selector:
                        el = await frame.query_selector(input_selector)
                        if el:
                            logger.info(f"Input-Feld in iframe gefunden (spezifisch): {frame.url[:80]}")
                            self._widget_frame = frame
                            return frame

                    el = await frame.query_selector(generic_selector)
                    if el:
                        logger.info(f"Input-Feld in iframe gefunden (generisch): {frame.url[:80]}")
                        self._widget_frame = frame
                        return frame
                except Exception:
                    continue

            elapsed += poll_interval
            if elapsed < max_wait:
                logger.debug(f"Input-Feld noch nicht gefunden, warte... ({elapsed:.0f}/{max_wait:.0f}s)")
                await asyncio.sleep(poll_interval)

        logger.error(f"Kein Input-Feld gefunden nach {max_wait}s Suche")
        return None

    async def send_message(self, message: str) -> Optional[str]:
        """Nachricht an den Chatbot senden und Antwort abwarten"""
        if not self.chatbot_info:
            logger.error("Kein Chatbot erkannt")
            return None

        # Spezialfall: KI-Textverarbeitungs-App (Textarea + Button)
        if self.chatbot_info.provider == "form_app":
            return await self._send_form_app_message(message)

        input_selector = self.chatbot_info.selector_set.get("input", "")
        message_selector = self.chatbot_info.selector_set.get("message", "")

        try:
            active_frame = await self._get_active_frame()
            if not active_frame:
                logger.error("Kein Input-Feld gefunden (weder Hauptseite noch iframes)")
                return None

            # Aktuellen Nachrichtenstand merken
            current_messages = await active_frame.query_selector_all(message_selector)
            msg_count_before = len(current_messages)

            # Input finden
            input_el = None
            if input_selector:
                input_el = await active_frame.query_selector(input_selector)
            if not input_el:
                input_el = await active_frame.query_selector(
                    'textarea, input[type="text"], [contenteditable="true"]'
                )

            if not input_el:
                logger.error("Kein Input-Feld gefunden")
                return None

            await input_el.click()
            await input_el.fill(message)
            await asyncio.sleep(0.5)

            # Enter drücken oder Send-Button klicken
            send_btn = await active_frame.query_selector(
                'button[type="submit"], button[class*="send"], '
                'button[aria-label*="send"], button[aria-label*="Send"], '
                'button[aria-label*="senden"], button[aria-label*="Senden"], '
                'button[class*="submit"]'
            )
            if send_btn:
                await send_btn.click()
            else:
                await input_el.press("Enter")

            logger.info(f"Nachricht gesendet: {message[:50]}...")

            response = await self._wait_for_response(
                message_selector, msg_count_before, frame=active_frame
            )
            return response

        except Exception as e:
            logger.error(f"Fehler beim Senden: {e}")
            return None

    async def _wait_for_response(
        self, message_selector: str, msg_count_before: int,
        timeout: float = 15.0, frame=None
    ) -> Optional[str]:
        """Auf neue Bot-Antwort warten"""
        ctx = frame or self.page
        elapsed = 0
        poll_interval = 0.5

        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            try:
                messages = await ctx.query_selector_all(message_selector)
                if len(messages) > msg_count_before:
                    last_msg = messages[-1]
                    content = await last_msg.text_content()
                    if content and content.strip():
                        logger.info(f"Antwort erhalten: {content[:80]}...")
                        return content.strip()
            except Exception:
                continue

        # Fallback: Chat-Area Text holen
        for selector in [
            '[class*="chat-body"]', '[class*="messages"]',
            '[class*="conversation"]', '.message-container',
            '[class*="content"]',
        ]:
            try:
                chat_area = await ctx.query_selector(selector)
                if chat_area:
                    text = await chat_area.text_content()
                    if text and text.strip():
                        return text.strip()
            except Exception:
                continue

        # Zweiter Fallback: Alle Frames durchsuchen
        if frame is None:
            for f in self.page.frames:
                try:
                    chat_area = await f.query_selector(
                        '[class*="chat-body"], [class*="messages"], '
                        '[class*="conversation"], .message-container'
                    )
                    if chat_area:
                        text = await chat_area.text_content()
                        if text and text.strip():
                            return text.strip()
                except Exception:
                    continue

        logger.warning("Timeout: Keine Antwort erhalten")
        return None

    async def send_multi_turn(self, messages: list[str]) -> list[ChatMessage]:
        """Mehrere Nachrichten nacheinander senden (für Multi-Turn Angriffe)"""
        conversation = []
        for msg in messages:
            response = await self.send_message(msg)
            conversation.append(ChatMessage(role="user", content=msg))
            if response:
                conversation.append(ChatMessage(role="assistant", content=response))
            await asyncio.sleep(1)
        return conversation

    async def take_screenshot(self, path: str):
        """Screenshot der aktuellen Seite"""
        await self.page.screenshot(path=path, full_page=True)
        logger.info(f"Screenshot gespeichert: {path}")

    async def _send_form_app_message(self, message: str) -> Optional[str]:
        """
        Nachricht an KI-Textverarbeitungs-App senden (Textarea + Button Muster).
        Robuster Ansatz: Snapshots des gesamten sichtbaren Texts vor/nach Submit.
        """
        try:
            # --- Schritt 1: Gesamten sichtbaren Seitentext vor Submit speichern ---
            text_before = await self.page.evaluate("""
                () => document.body.innerText
            """)

            # --- Schritt 2: Textarea finden und befüllen ---
            textarea = await self.page.query_selector('textarea')
            if not textarea:
                logger.error("Form-App: Keine Textarea gefunden")
                return None

            await textarea.click()
            await asyncio.sleep(0.3)

            # Textarea vollständig leeren und neu befüllen
            await textarea.evaluate('el => { el.value = ""; el.dispatchEvent(new Event("input", {bubbles:true})); }')
            await asyncio.sleep(0.2)
            await textarea.fill(message)
            await asyncio.sleep(0.5)
            logger.info(f"Form-App: Text eingegeben ({len(message)} Zeichen)")

            # --- Schritt 3: Submit-Button finden und klicken ---
            submit_btn = await self._find_form_submit_button()
            if not submit_btn:
                logger.error("Form-App: Kein Submit-Button gefunden")
                return None

            await submit_btn.click()
            logger.info("Form-App: Submit-Button geklickt")

            # --- Schritt 4: Auf Ergebnis warten ---
            response_text = await self._wait_for_form_app_response(text_before)
            return response_text

        except Exception as e:
            logger.error(f"Form-App Fehler: {e}")
            return None

    async def _find_form_submit_button(self):
        """
        Findet den Submit-Button einer Form-App.
        Re-queried jedes Mal (React-Apps rendern Buttons neu).
        """
        button_text = self.chatbot_info.selector_set.get("submit_button", "")

        # Alle sichtbaren Buttons durchsuchen
        buttons = await self.page.query_selector_all('button')
        for btn in buttons:
            try:
                visible = await btn.is_visible()
                if not visible:
                    continue
                text = await btn.text_content()
                if not text:
                    continue
                text_lower = text.strip().lower()

                # Match auf bekannten Button-Text
                if button_text and button_text.lower() in text_lower:
                    return btn

                # Generische KI-App Button-Keywords
                keywords = [
                    'übersetzen', 'translate', 'analysieren', 'analyze',
                    'zusammenfass', 'summarize', 'generieren', 'generate',
                    'submit', 'senden', 'verarbeiten', 'process',
                    'starten', 'start', 'check', 'prüfen', 'auswerten',
                    'umwandeln', 'convert', 'erstellen', 'create',
                ]
                if any(kw in text_lower for kw in keywords):
                    return btn
            except Exception:
                continue

        return None

    async def _wait_for_form_app_response(
        self, text_before: str, timeout: float = 30.0
    ) -> Optional[str]:
        """
        Wartet auf die Antwort einer KI-Textverarbeitungs-App.
        Vergleicht den gesamten sichtbaren Seitentext vor und nach Submit,
        extrahiert den neuen/geänderten Teil.
        """
        elapsed = 0
        poll_interval = 1.5
        last_diff = ""
        stable_count = 0

        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            try:
                # Aktuellen Seitentext holen
                text_after = await self.page.evaluate("""
                    () => document.body.innerText
                """)

                # Diff: Was ist NEU im Seitentext?
                diff = self._extract_new_text(text_before, text_after)

                if diff and len(diff) > 20:
                    # Stabilisierung: Warten bis der Diff sich nicht mehr ändert
                    if diff == last_diff:
                        stable_count += 1
                        if stable_count >= 2:
                            logger.info(f"Form-App Antwort stabil ({len(diff)} Zeichen)")
                            return diff
                    else:
                        last_diff = diff
                        stable_count = 0
                        logger.debug(f"Form-App: Neuer Content ({len(diff)} Zeichen), warte auf Stabilisierung...")

                # Loading-Indicator prüfen (Button disabled = noch am Laden)
                is_loading = await self.page.evaluate("""
                    () => {
                        // Disabled buttons
                        const btns = document.querySelectorAll('button[disabled]');
                        if (btns.length > 0) return true;
                        // Spinners
                        const spinners = document.querySelectorAll(
                            '[class*="loading"], [class*="spinner"], [class*="progress"], ' +
                            '[role="progressbar"], [aria-busy="true"], ' +
                            '.animate-spin, [class*="animate"]'
                        );
                        for (const s of spinners) {
                            if (s.offsetParent !== null) return true;
                        }
                        return false;
                    }
                """)
                if is_loading and elapsed > timeout - 5:
                    timeout += 10
                    logger.info(f"Form-App: Timeout verlängert auf {timeout}s (Loading aktiv)")

            except Exception as e:
                logger.debug(f"Form-App Poll-Fehler: {e}")

        if last_diff:
            logger.info(f"Form-App: Timeout, aber letzter Diff ({len(last_diff)} Zeichen)")
            return last_diff

        logger.warning(f"Form-App: Keine Antwort nach {timeout}s")
        return None

    def _extract_new_text(self, before: str, after: str) -> str:
        """
        Extrahiert den neuen Text der nach dem Submit erschienen ist.
        Vergleicht Zeilen des Seitentexts vor/nach Submit.
        """
        before_lines = set(before.strip().splitlines())
        after_lines = after.strip().splitlines()

        # Neue Zeilen sammeln (die vorher nicht da waren)
        new_lines = []
        for line in after_lines:
            stripped = line.strip()
            if stripped and stripped not in before_lines:
                new_lines.append(stripped)

        if not new_lines:
            return ""

        return "\n".join(new_lines)

    async def get_page_content(self) -> str:
        """Gesamten Seiteninhalt holen (für passive Analyse)"""
        return await self.page.content()
