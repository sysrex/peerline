# Webhooks

Peerline signs outbound webhooks with [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks) version 1.

## Headers

- `webhook-id`: stable event id. Receivers use it as the idempotency key. Retries send the same id.
- `webhook-timestamp`: unix seconds.
- `webhook-signature`: one or more `v1,<base64>` values separated by spaces. During secret rotation both the current and previous secret are included.

The MAC is HMAC-SHA256 over `webhook-id + "." + webhook-timestamp + "." + body`, keyed by the raw bytes of the `whsec_` secret.

## Verify

Reject timestamps more than 5 minutes from your clock. Compare the signature in constant time. A placeholder secret looks like `whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3`; it is not a real credential.

A `410 Gone` response disables the endpoint. Other failures retry with exponential backoff, capped at 6 hours, and stop after 8 attempts.

## Destination rules

URLs must be HTTPS with no userinfo, query, or fragment. The client resolves the name and dials only public addresses, so a name that first resolves publicly and then to a private address is still refused. Redirects are refused.
