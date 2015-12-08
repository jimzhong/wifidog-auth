#!/usr/bin/python3
# -*- coding: utf-8 -*-
import logging
logging.basicConfig(level=logging.DEBUG)

from . import app

app.run(host="0.0.0.0")