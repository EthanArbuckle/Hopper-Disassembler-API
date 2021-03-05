#
#  hopper_proxy.py
#  IDA Objc
#  
#  Created by Ethan Arbuckle on 2021-03-05
#  Copyright (c) 2021 Ethan Arbuckle and Tanner Bennett. All rights reserved.
#

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer


class ListSegments:
    PATH = "/segments"

    @classmethod
    def run(cls):
        segments = Document.getCurrentDocument().getSegmentsList()
        return [segment.getName() for segment in segments]


class ListProcedures:
    PATH = "/procedures"

    @classmethod
    def run(cls, segment_name):
        if not segment_name:
            raise Exception("did not specify a segment name")

        segment = Document.getCurrentDocument().getSegmentByName(segment_name)

        named_procedures = []
        for label_name, label_address in zip(
            segment.getLabelsList(), segment.getNamedAddresses()
        ):
            named_procedures.append(
                {
                    "label": label_name,
                    "address": label_address,
                }
            )

        return named_procedures


class DecompileProcedure:
    PATH = "/decompile"

    @classmethod
    def run(cls, segment_name, procedure_address):
        if not procedure_address or not segment_name:
            raise Exception("did not specify a segment name or procedure address")

        seg = Document.getCurrentDocument().getSegmentByName(segment_name)
        procedure = seg.getProcedureAtAddress(procedure_address)

        return procedure.decompile()


class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        posted_data = (
            json.loads(self.rfile.read(content_length)) if content_length > 0 else {}
        )

        data_response = None
        error = None

        for handler in [ListSegments, ListProcedures, DecompileProcedure]:
            if self.path == handler.PATH:

                try:
                    data_response = handler.run(**posted_data)
                    json.dumps(data_response)
                    self.send_response(200)
                except TypeError as e:
                    self.send_response(500)
                    error = str(e)
                except Exception as e:
                    self.send_response(500)
                    error = str(e)

                response = { "data": data_response }
                if error:
                    response["error"] = error
                
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode("utf-8"))


httpd = HTTPServer(("", 3100), RequestHandler)

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass

httpd.server_close()
