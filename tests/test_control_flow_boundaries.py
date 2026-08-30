import unittest

from control_flow import analyze_control_flow


class ControlFlowBoundaryTests(unittest.TestCase):
    def test_fallthrough_never_crosses_control_section_boundary(self):
        image = bytes.fromhex("010001010002")
        debug = {
            "sections": [
                {
                    "input_index": 0,
                    "section_index": 0,
                    "name": "ONE",
                    "load_address": 0x4000,
                    "length": 3,
                    "typed": True,
                    "symbols": [],
                    "regions": [
                        {
                            "loaded_address": 0x4000,
                            "length": 3,
                            "kind": "instruction",
                            "expanded_line": 1,
                            "symbols": [],
                            "provenance": None,
                        }
                    ],
                },
                {
                    "input_index": 0,
                    "section_index": 1,
                    "name": "TWO",
                    "load_address": 0x4003,
                    "length": 3,
                    "typed": True,
                    "symbols": [],
                    "regions": [
                        {
                            "loaded_address": 0x4003,
                            "length": 3,
                            "kind": "instruction",
                            "expanded_line": 2,
                            "symbols": [],
                            "provenance": None,
                        }
                    ],
                },
            ]
        }
        report = analyze_control_flow(image, 0x4000, debug, 0x4000)
        self.assertFalse(any(edge["source"] == 0x4000 for edge in report["edges"]))
        nodes = {item["address"]: item for item in report["instructions"]}
        self.assertTrue(nodes[0x4000]["reachable"])
        self.assertFalse(nodes[0x4003]["reachable"])

    def test_indirect_jump_is_not_fabricated_as_static_edge(self):
        # J @00006 is followed by another typed instruction at 04003. The
        # encoded field identifies an indirect pointer address, not a statically
        # known instruction target, so no direct CFG edge may be fabricated.
        image = bytes.fromhex("3E00064F0000")
        debug = {
            "sections": [
                {
                    "input_index": 0,
                    "section_index": 0,
                    "name": "MAIN",
                    "load_address": 0x4000,
                    "length": 6,
                    "typed": True,
                    "symbols": [],
                    "regions": [
                        {
                            "loaded_address": 0x4000,
                            "length": 3,
                            "kind": "instruction",
                            "expanded_line": 1,
                            "symbols": [],
                            "provenance": None,
                        },
                        {
                            "loaded_address": 0x4003,
                            "length": 3,
                            "kind": "instruction",
                            "expanded_line": 2,
                            "symbols": [],
                            "provenance": None,
                        },
                    ],
                }
            ]
        }
        report = analyze_control_flow(image, 0x4000, debug, 0x4000)
        jump = next(edge for edge in report["edges"] if edge["kind"] == "jump")
        self.assertFalse(jump["resolved"])
        self.assertEqual(jump["reason"], "indirect")
        self.assertIsNone(jump["target"])
        self.assertEqual(report["reachable_instruction_count"], 1)


if __name__ == "__main__":
    unittest.main()
