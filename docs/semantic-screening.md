# Local semantic screening

`LocalSemanticDetector(model_path, *, malicious_labels, max_input_bytes=65536)`
loads a preinstalled Transformers text classification model. `score(payload)` takes
text or a JSON object and returns a float probability in [0, 1]. The trusted engine
owns the blocking threshold and must block on `SemanticScreeningError` whenever
screening is enabled. A low score cannot grant a capability or erase provenance.

Provision the optional Transformers/PyTorch runtime and an independently reviewed,
pinned model snapshot before enabling this layer. Configure an absolute existing
local directory; repository IDs and relative paths are rejected. The adapter loads
only local tokenizer/model files, disables remote code, and requires safetensors
weights. It never downloads a model. Restrict filesystem modification of this
trusted directory. Record the upstream revision and file hashes when provisioning.

One compatible purpose-trained model is
[ProtectAI/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2).
Its [configuration](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/blob/main/config.json)
defines SAFE and INJECTION labels and a 512-token context. Configure
`malicious_labels={"INJECTION"}`. The model weights are about 738 MB; this repository
does not bundle them; provision them separately as recorded below. The upstream project is archived. Its
[model card](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/blob/main/README.md)
limits its intended coverage to English injection detection and warns about false
positives on system prompts. Review deployment fitness independently.

The adapter checks the entire UTF-8 input size and tokenizes without truncation,
including special tokens. Inputs beyond either bound are rejected, even if their
prefix looks benign. JSON objects are serialized in full, including keys. No
chunk splitting or partial-coverage allowance is used. Missing runtime/model files,
missing context limits, inference failures, unrecognized/duplicate/missing labels,
and malformed or non-normalized probabilities raise `SemanticScreeningError`.
This implementation expects mutually exclusive classification probabilities.

The optional `pipeline` constructor argument is an external inference boundary for
unit tests only. Tests supply fixed classifier-output fixtures and exercise label
mapping, validation, context rejection and error behavior; they do not establish
real semantic model accuracy. Real-model evaluation requires separately provisioned
weights and representative held-back hostile and benign corpora. Never accept a
pipeline object or label mapping from an untrusted request.

Deterministic screening additionally inspects at most three text copies: original
and up to two bounded normalization passes using NFKC, format-character removal,
URL decoding and HTML entity decoding. It also examines one base64 decoding layer
and normalizes the decoded copy. Original payloads are never rewritten. Findings
from copies use null spans because normalized offsets cannot safely identify an
original substring; the engine must block those findings. Oversize strings produce
a blocking finding. Attacker-controlled phrases such as "attack example" and
"quotes" do not reduce severity. This deliberately changes earlier permissive
quoted-attack behavior and may increase false positives. Arbitrary encodings,
homoglyphs and deeply nested obfuscation are outside these bounded heuristics.

## Verified local provision (2026-10-24)

For a fresh installation, run from the project root:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[semantic]"
.\.venv\Scripts\python.exe -c "from huggingface_hub import snapshot_download; snapshot_download(repo_id='ProtectAI/deberta-v3-base-prompt-injection-v2', revision='90c9989b1a342275dd0d1a95aad283c04e075671', local_dir='.models/prompt-injection', allow_patterns=['config.json','model.safetensors','tokenizer.json','tokenizer_config.json','special_tokens_map.json','added_tokens.json','spm.model'])"
```

Provisioning requires internet access and sufficient disk space. This explicit
download happens before inference. If your host environment has `HF_HUB_OFFLINE=1`,
unset it for provisioning and restore it afterward. The workspace provision used
the PyTorch CPU wheel index to avoid installing a GPU runtime.

Set these values in `.env`, using the absolute model directory on your machine:

```dotenv
FIREWALL_SEMANTIC_MODEL_PATH=C:/absolute/path/to/Cognitive-Firewall/.models/prompt-injection
FIREWALL_SEMANTIC_LABELS=INJECTION
FIREWALL_SEMANTIC_THRESHOLD=0.8
HF_HUB_OFFLINE=1
TRANSFORMERS_OFFLINE=1
HF_HUB_DISABLE_TELEMETRY=1
```

Restart the API and check operator-authenticated `GET /v1/security/status` for
`"semantic_screening":"enabled"`. In this workspace these settings have now been
applied and the restarted API passed the live probes recorded in
[verification](verification-2026-10-24.md).

This workspace now has the real model in `.models/prompt-injection`, downloaded at
revision `90c9989b1a342275dd0d1a95aad283c04e075671` from the upstream repository above.
The seven required files occupy 748,843,219 bytes (about 714 MiB). The safetensors
SHA-256 is `6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424`.
The local `provisioning-manifest.json` records every file hash and size. Model assets
are local runtime data and should remain excluded from version control.

The virtual environment has Transformers 4.57.6, torch 2.14.1+cpu, and sentencepiece
0.2.2. `pip check` reported no broken requirements. An actual adapter smoke run with
`HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` loaded the model in 5.484 seconds,
then scored these synthetic fixtures on CPU:

| Fixture | INJECTION probability | Inference seconds |
| --- | ---: | ---: |
| Quarterly report summarization request | 0.0000009392 | 0.219 |
| Explicit override with secret disclosure and exfiltration | 0.9999997616 | 0.094 |
| Paraphrased administrator policy change asking for confidential context | 0.9999997616 | 0.187 |

These three cases establish that the installed real model runs through the adapter;
they do not establish broad accuracy. The earlier fixture-based adapter tests remain
unit tests. A torch deprecation warning was emitted during loading; inference
completed successfully. Provisioning alone does not enable screening in a running
service; service configuration and restart are separate operator actions.


