import unittest

from memory_postconditions import _attach_value_facts


class MemoryPostconditionRevocationTests(unittest.TestCase):
    def test_widened_memory_value_revokes_previous_exact_and_range_facts(self):
        node = {
            "address": 0x4000,
            "base_mnemonic": "LDB",
            "memory_constant": None,
            "memory_range": None,
            "loaded_register_constant": None,
            "loaded_register_range": None,
        }
        first = {
            "instruction_facts": {
                0x4000: {
                    "memory_read": "04020+3",
                    "constant": 7,
                    "range": [7, 7],
                    "origin": "callee-return@04010",
                }
            }
        }
        _attach_value_facts([node], first)
        self.assertEqual(node["memory_constant"], 7)
        self.assertEqual(node["memory_range"], [7, 7])
        self.assertEqual(node["loaded_register_constant"], {"register": "B", "value": 7})

        widened = {
            "instruction_facts": {
                0x4000: {
                    "memory_read": "04020+3",
                    "constant": None,
                    "range": None,
                    "origin": None,
                }
            }
        }
        _attach_value_facts([node], widened)
        self.assertIsNone(node["memory_constant"])
        self.assertIsNone(node["memory_range"])
        self.assertIsNone(node["loaded_register_constant"])
        self.assertIsNone(node["loaded_register_range"])
        self.assertEqual(node["memory_value_resolution"], "abstract-memory-value")


if __name__ == "__main__":
    unittest.main()
