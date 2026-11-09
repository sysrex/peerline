# A2A tasks

| A2A | Peerline |
|---|---|
| Agent | Peer |
| Message, text or data parts | A message of type `a2a.message` whose body is the JSON envelope `{messageId, contextId, taskId, role, parts}` |
| Envelope size | 4096 bytes for the whole envelope |
| `raw` or `url` parts | Rejected until a later large-payload change |
| `contextId` | `a2a_tasks.context_id` |
| `taskId` and `referenceTaskIds` | `a2a_msg_map` links an A2A message id to a Peerline message id and a task |
| Artifact | Inline JSON, at most 64 KiB |

The executor reads the inbox and answers with `PUT /v1/a2a/tasks/{id}`. Only that peer can change state. The client and the executor can read the task. Anyone else gets the same not-found error as a missing id.

Terminal states are `completed`, `failed`, `canceled`, and `rejected`. A message to a terminal task is refused. Canceling a terminal task is refused separately.

Creating a task records `task.created`. An answer records `task.status`, and `artifact.update` when artifacts are included. Tasks expire after 30 days and are purged in batches.
