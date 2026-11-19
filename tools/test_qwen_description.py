import base64
import json
import tempfile
import threading
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer
import unittest
from pathlib import Path

import qwen_description as qwen


def response(content, *, finish="stop", **message):
    return json.dumps({"choices": [{
        "finish_reason": finish, "message": {"content": content, **message},
    }]}).encode()


class QwenDescriptionTests(unittest.TestCase):
    def test_request_uses_synthetic_image_inline_and_disables_thinking(self):
        image = qwen.synthetic_png((255, 0, 0), False)
        body = qwen.request_body(image)
        data = body["messages"][0]["content"][0]["image_url"]["url"]
        self.assertEqual(base64.b64decode(data.split(",", 1)[1]), image)
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})
        self.assertFalse(body["response_format"]["json_schema"]["schema"]["additionalProperties"])

    def test_worker_labels_binary_jpeg_and_caps_images_before_encoding(self):
        jpeg = bytes.fromhex("ffd8ffe0")
        body = qwen.request_body(jpeg)
        self.assertEqual(
            body["messages"][0]["content"][0]["image_url"]["url"],
            "data:image/jpeg;base64," + base64.b64encode(jpeg).decode(),
        )
        with patch.object(qwen, "MAX_IMAGE", len(jpeg) - 1), self.assertRaisesRegex(ValueError, "input limit"):
            qwen.request_body(jpeg)

    def test_description_maps_to_worker_wire_contract(self):
        result = qwen.worker_output(response('{"description":"A red square."}'))
        self.assertEqual(result[qwen.DESCRIPTION_TASK], {
            "description": "A red square.", "people": [], "environment": "",
            "objects": [], "visible_text": [], "context": "", "tags": [],
        })

    def test_refuses_unbounded_reasoning_ambiguous_and_truncated_responses(self):
        for raw in (
            b"[]", b" " * (qwen.LIMIT + 1),
            response('{"description":"A","description":"B"}'),
            response('{"description":"A","tags":["unexpected"]}'),
            response('{"description":"<think>answer</think>"}'),
            response('{"description":"A"}', finish="length"),
            response('{"description":"A"}', reasoning_content="hidden reasoning"),
            response(json.dumps({"description": "x" * 241})),
        ):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                qwen.worker_output(raw)

    def test_http_transport_sends_the_fixture_only_to_the_authenticated_loopback_server(self):
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                observed.append((self.path, self.headers["Authorization"], json.loads(body)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response('{"description":"A red square."}'))

            def log_message(self, *_args):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            server.timeout = 2
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            image = qwen.synthetic_png((255, 0, 0), False)
            try:
                result = qwen.predict_worker(server.server_port, "fixture", qwen.worker_entries(), image)
                self.assertEqual(result[qwen.DESCRIPTION_TASK]["description"], "A red square.")
            finally:
                thread.join(timeout=2)
            self.assertEqual(observed, [("/v1/chat/completions", "Bearer fixture", qwen.request_body(image))])

    def test_native_prediction_refuses_wrong_binding_or_image_before_transport(self):
        image = qwen.synthetic_png((255, 0, 0), False)
        for entries, payload in (
            ({}, image),
            ({qwen.DESCRIPTION_TASK: {"visual": {"modelName": "other", "options": {}}}}, image),
            ({qwen.DESCRIPTION_TASK: {"visual": {"modelName": "Qwen3.5-4B", "options": {"external_prompt": "new instructions"}}}}, image),
            (qwen.worker_entries(), b"file:///tmp/private.jpg"),
        ):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                qwen.predict_worker(0, "fixture", entries, payload)

    def test_refuses_mismatched_candidate_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model"
            path.write_bytes(b"mock")
            with self.assertRaisesRegex(ValueError, "size"):
                qwen.checked_artifact(path, (3, "0" * 64))
            with self.assertRaisesRegex(ValueError, "digest"):
                qwen.checked_artifact(path, (4, "0" * 64))
