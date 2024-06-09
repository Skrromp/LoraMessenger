from threading import Thread

from kivy.lang import Builder
from kivymd.app import MDApp
import LoraMessenger.lora_messageService as lora_messageService
import re

class KivyApp(MDApp):

    def __init__(self):
        super(KivyApp, self).__init__()
        self.controller = lora_messageService.LoraController(self)
        self.pattern = re.compile("[a-zA-Z0-9 ]*[,][0-9]")

    def build(self):
        self.theme_cls.primary_palette = "DeepPurple"
        self.theme_cls.accent_palette = "DeepPurple"

        return Builder.load_file("SerialConsoleMessenger.kv")

    def process_input(self):
        text = self.root.ids.inputField.text
        if self.pattern.match(text) is None:
            self.write_to_console_log("Input format is not valid, please try again")
        else:
            Thread(target=kivy_app.controller.send_message, args=[text]).start()
            self.write_to_input_log(text)
        self.root.ids.inputField.text = ""

    def write_to_debug_log(self, output: str):
        self.root.ids.debugLog.text += output + "\n"

    def write_to_input_log(self, output: str):
        self.root.ids.debugLog.text += output + "\n"

    def write_to_console_log(self, output: str):
        self.root.ids.consoleLog.text += output + "\n"


kivy_app = KivyApp()
kivy_app.controller.setup()

Thread(target=kivy_app.controller.receiving_loop,).start()
Thread(target=kivy_app.controller.process_sendings,).start()
kivy_app.run()

