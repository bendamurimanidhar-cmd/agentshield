# Stage 2 Review: Data Loss Prevention (DLP) & Credential Redactor
**Lead Documentarians:** Privacy & Compliance Squad  
**Target:** PII & Secrets Sanitizer  

### What Was Done in This Stage:
1. Built scanners for API tokens (OpenAI, AWS, GitHub), bearer secrets, passwords, and sensitive identifiers.
2. Added automatic in-place redaction, replacing raw keys with `[REDACTED_*]` placeholders.
3. Protected user privacy by stopping credit cards and SSNs from leaking into model training contexts.

### Human English Summary:
This stage makes sure secrets never leave your servers. If a user accidentally pastes an AWS password, credit card, or secret token, AgentShield blanks it out immediately before sending the prompt to the AI.
