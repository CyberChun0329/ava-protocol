# AVA Protocol Agent SDK

This optional ESM package offers `AvaDecisionAgent` and a host-supplied `ChoiceProvider` for decision advice. Node.js 24 or later is required. Install the matching SDK and agent archives together in an independent project:

```sh
npm install ./ava-protocol-sdk-0.1.0.tgz ./ava-protocol-agent-sdk-0.1.0.tgz
```

```js
import { AvaDecisionAgent } from '@ava-protocol/agent-sdk';
const agent = new AvaDecisionAgent(extensions, actor); // Host supplies both.
const advice = await agent.advise(client, requestId, provider, input);
```

Your application chooses the provider and the data it receives. The SDK returns advice. To act on it, the application uses an authorised actor and the regular AVA signing and execution path. See LICENSE and NOTICE for the Apache-2.0 terms.

For OpenAI Decisions, supply a client from the host application and use the preset:

```js
import OpenAI from 'openai';
import { openAIDecisions } from '@ava-protocol/agent-sdk';

const openai = new OpenAI(); // The host configures credentials and client settings.
const provider = openAIDecisions({ client: openai }); // Defaults to gpt-6-luna.
// To choose a model explicitly: openAIDecisions({ client: openai, model: 'your-model' });
```

Configure credentials, retries and timeouts in your client. Send only material the provider is allowed to receive.

For a third-party or self-hosted model, implement `ChoiceProvider`. Configure the key, URL, headers and transport in your client and map its response to `choice` or `abstain`. Check whether an OpenAI-compatible endpoint supports Decisions before choosing that adapter. To use `ollamaChoices` or `localSystemOneChoices`, install the engine and model separately and supply the `chat` or `systemOne` callback.

OpenAI Choice requires at least two options. If given fewer, both adapters return `abstain` before calling the client. `AvaDecisionAgent` returns `abstained` advice for the application to route for review. It produces no executable command in that case.

Abstained receipts distinguish `insufficient_options`, `provider_refusal`, `provider_abstained`, `low_confidence` and `missing_confidence`, retaining available response/model metadata. `AvaAgentError.code` distinguishes `cancelled`, `timeout`, `transport_error`, `invalid_response`, `invalid_configuration` and `invalid_advice` without exposing upstream messages or causes. Legacy custom `{ kind: 'abstain' }` answers remain valid. Providers without a documented refusal format do not receive an invented one.

For an application-owned handoff, keep the original advice, pass `parentReceiptHash: adviceReceiptHash(original.receipt)` into the next actor's independent `advise` call, then use `linkAdvice(original, next)` to validate the same-case link. The next receipt and existing decision reason hash commit the parent digest. Store both advice records, the link, and the resulting transaction/decision IDs privately. This does not choose a reviewer, grant their authority, or prove model execution/human review. Recompute current actor eligibility before signing as usual.

`buildCommand` verifies a present receipt `snapshotHash` against the complete supplied snapshot and refuses modified public labels. Legacy receipts without that field retain current-context command validation, but cannot form an offline `linkAdvice` handoff. Neither format proves model execution or grants signing authority.
