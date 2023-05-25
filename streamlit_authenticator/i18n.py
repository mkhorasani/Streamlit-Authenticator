import glob
import os
import yaml
from datetime import datetime
from babel.dates import format_datetime
import streamlit as st

DEFAULT_LOCALE = "en-US"


class Translator:
    def __init__(self, translations_folder, default_locale=DEFAULT_LOCALE):
        # initialization
        self.locale = default_locale
        self.data = Translator._get_translation_data(translations_folder)

    @st.cache_data
    @staticmethod
    def _get_translation_data(translations_folder):
        data = {}

        # get list of files with specific extensions
        files = glob.glob(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                translations_folder,
                f"*.yaml",
            )
        )
        for fil in files:
            # get the name of the file without extension, will be used as locale name
            loc = os.path.splitext(os.path.basename(fil))[0]
            with open(fil, "r", encoding="utf8") as f:
                data[loc] = yaml.safe_load(f)

        return data

    def set_locale(self, loc):
        if loc in self.data:
            self.locale = loc
        else:
            print("Invalid locale")

    def get_locale(self):
        return self.locale

    def translate(self, key):
        # return the key instead of translation text if locale is not supported
        if self.locale not in self.data:
            return key

        text = self.data[self.locale].get(key, self.data[DEFAULT_LOCALE].get(key, key))

        return text
