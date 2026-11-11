import base64
import json
import tempfile
import threading
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
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            request = qwen.request_body(qwen.synthetic_png((255, 0, 0), False))
            connection, reply = qwen.request_local(server.server_port, "/v1/chat/completions", "fixture", body=request)
            try:
                self.assertEqual(qwen.worker_output(reply.read())[qwen.DESCRIPTION_TASK]["description"], "A red square.")
            finally:
                connection.close()
                thread.join(timeout=2)
            self.assertEqual(observed, [("/v1/chat/completions", "Bearer fixture", request)])

    def test_refuses_mismatched_candidate_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model"
            path.write_bytes(b"mock")
            with self.assertRaisesRegex(ValueError, "size"):
                qwen.checked_artifact(path, (3, "0" * 64))
            with self.assertRaisesRegex(ValueError, "digest"):
                qwen.checked_artifact(path, (4, "0" * 64))
