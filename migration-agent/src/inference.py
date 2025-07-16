"""
This defines the routines for using LLMs for inference
"""

from pathlib import Path
import json
import demjson3
import logging
from json import JSONDecoder
from utilities.llms import LLM
from utilities.utilities import pretty_print_code, pretty_print_dialog
from global_config import *
import re


class LLMRepair:

    def __init__(self):
        self.llm = LLM()
        self.repair_prompt_template = (
            "Given the following LLVM/Clang compilation errors, compiler command, and source code, provide a solution to fix the error. "
            "If this can be fixed by modifying the code, provide the revised code (as a whole) and reasoning in a JSON object. "
            "If this can be fixed by changing the compiler options, place the new compiler command in the 'compiler_options' field along with reasoning. "
            'Organise the code change per file. A json output example could be json {"code_changes":{"path to the source file": "code"}, "compiler_options", "compiler_options", "reasoning", "reasoning"} '
            "Ensure that strings (especially multiline strings) are properly escaped, but do not just escape space. "
            "Do not produce text other than the JSON object. Keep the reasoning text concise."
        )

        self.template_code_suffix = "The code from [SOURCE_FILE] is: ``` [CODE] ```, "
        self.repair_prompt_template_suffix = (
            "the compiler command is: ``` [COMMAND] ```, "
            "the compilation error is: ``` [ERROR] ```"
        )
        self.extract_prompt_template = (
            "I want you to act as an expert programmer to help me fix a compilation error. "
            "Given the following compilation error message and content of the relevant file, determine if there is additional source file you "
            "need to see to diagnose the issue."
            "Respond in JSON format with two fields: "
            "source_file: The name of the source file you need to see. If the issue can be "
            "resolved without viewing any source file, return None. "
            "reasoning: A brief explanation of why this file is needed or why no file is required."
            "Do not show your reasoning process, only return the JSON response and ensure valid JSON escapes."
        )
        self.extract_prompt_template_suffix = (
            "the compiler command is: ``` [COMMAND] ```, "
            "the compilation error is: ``` [ERROR] ```, "
        )

    # Get prompt template
    def get_repair_prompt_template(self):
        return self.repair_prompt_template

    # Return the model id (name) used for inference
    def get_model_id(self):
        return self.llm.get_model_id()

    def extract_json_objects(self, text, decoder=JSONDecoder()):
        """Extracts JSON objects from text."""
        pos = 0
        while True:
            match = text.find("{", pos)
            if match == -1:
                break
            try:
                result, index = decoder.raw_decode(text[match:])
                yield result
                pos = match + index
            except ValueError:
                pos = match + 1

    def _extract_code_changes(self, code_changes):
        """Extract and log code changes from LLM response."""
        code = {}
        if code_changes:
            for source, code_text in code_changes.items():
                code[source] = code_text
                logging.debug(
                    pretty_print_code(f"LLM Generated Code for {source}", code_text)
                )
        return code

    def _extract_compiler_options(self, data):
        """Extract compiler options from LLM response."""
        compiler_options = data.get("compiler_options")
        if compiler_options:
            logging.debug(
                pretty_print_dialog("LLM suggested options", compiler_options)
            )
        return compiler_options

    def _extract_reasoning(self, data, reasoning_content):
        """Extract reasoning from LLM response."""
        reasoning = data.get("reasoning")
        return reasoning if reasoning else reasoning_content

    def _extract_source_target(self, data):
        """Extract the source file required from LLM response."""
        return data.get("source_file")

    def process_response(self, message_content, reasoning_content):
        # Remove redundant texts before ``json {
        def remove_redundant_text(input_string):
            # Use regular expression to remove everything before the `json{...}` part
            cleaned_string = re.sub(
                r".*```json\s*{", "```json {", input_string, flags=re.DOTALL
            )
            return cleaned_string

        logging.debug(pretty_print_dialog("LLM inference raw data", message_content))
        # if reasoning_content:
        #   logging.debug(pretty_print_dialog("CoT raw data", reasoning_content))

        message_content = remove_redundant_text(message_content)
        message_content = message_content.replace("```json", "").replace("```", "")
        try:
            # logging.debug(f"RAW JSON DATA {message_content}")
            data = demjson3.decode(message_content)
        except Exception as e:
            logging.debug(f"Failed to parse json data {message_content} {e}")
            return {}
            # data = next(self.extract_json_objects(message_content))

        res = {
            "code": self._extract_code_changes(data.get("code_changes")),
            "compiler_options": self._extract_compiler_options(data),
            "reasoning": self._extract_reasoning(data, reasoning_content),
            "source_file": self._extract_source_target(data),
        }

        return res

    def populate_prompt_template(self, template: str, command: str, error: str) -> str:
        """Populate the prompt template with command and error."""
        return template.replace("[COMMAND]", command).replace("[ERROR]", error)

    def populate_code_to_prompt(self, prompt, code: dict):
        if code:
            for file, c in code.items():
                prompt += self.template_code_suffix.replace(
                    "[SOURCE_FILE]", file
                ).replace("[CODE]", c)
        return prompt

    def query_llm_for_fix(
        self, code: dict, command, error, prompt_template=None, model_id=None
    ):
        """Query LLM for fix based on code, command, and error."""
        prompt = prompt_template or self.repair_prompt_template
        prompt = self.populate_code_to_prompt(prompt=prompt, code=code)
        prompt += self.repair_prompt_template_suffix
        return self.inference(
            prompt=self.populate_prompt_template(prompt, command, error),
            model_id=model_id,
            task_msg="to repair errors.",
        )

    def query_llm_for_source_file(
        self, code: dict, command, error, prompt_template=None, model_id=None
    ):
        """Query LLM for the source file required to fix the issue."""
        prompt = prompt_template or self.extract_prompt_template
        prompt += self.extract_prompt_template_suffix
        prompt = self.populate_code_to_prompt(prompt=prompt, code=code)
        return self.inference(
            prompt=self.populate_prompt_template(prompt, command, error),
            model_id=model_id,
            task_msg="to locate relevant source files.",
        )

    def inference(self, prompt, model_id=None, task_msg=""):
        """Perform inference by querying the LLM."""
        prev_model = self.llm.get_model_id()
        if model_id:
            self.llm.set_model_id(model_id)
        else:
            model_id = self.llm.get_model_id()

        logging.info(f"Calling {model_id} {task_msg}")
        # logging.debug(f"prompt={prompt}")
        response = self.llm.inference(prompt)

        if response:
            data = json.loads(response.text)
            message_content = data.get("choices")[0].get("message").get("content")
            reasoning_content = (
                data.get("choices")[0].get("message").get("reasoning_content")
            )
            self.llm.set_model_id(prev_model)
            return self.process_response(message_content, reasoning_content)

        logging.error("Failed in getting the inference response")
        self.llm.set_model_id(prev_model)
