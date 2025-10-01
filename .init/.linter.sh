#!/bin/bash
cd /home/kavia/workspace/code-generation/jira-confluence-connect-145341-145351/backend_fastapi
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

