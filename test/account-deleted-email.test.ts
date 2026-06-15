import { describe, expect, it, vi } from "vitest";
import { sendAccountDeletedEmail } from "../src/alerts/email.js";
import {
  renderAccountDeletedHtml,
  renderAccountDeletedSubject,
  renderAccountDeletedText,
} from "../src/alerts/templates.js";

const INPUT = { email: "alice@example.com" };

describe("account-deleted email template", () => {
  it("subject names the account deletion", () => {
    expect(renderAccountDeletedSubject()).toMatch(/deleted/i);
  });

  it("text body confirms permanent erasure and points at support", () => {
    const text = renderAccountDeletedText(INPUT);
    expect(text).toMatch(/deleted/i);
    expect(text).toMatch(/support@dmarc\.mx/);
  });

  it("html body escapes the address and is a full document", () => {
    const html = renderAccountDeletedHtml({ email: "a<b>@x.com" });
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("a&lt;b&gt;@x.com");
    expect(html).not.toContain("<b>@x.com");
  });
});

describe("sendAccountDeletedEmail", () => {
  it("returns no_binding when the EMAIL binding is absent (self-host/test)", async () => {
    const outcome = await sendAccountDeletedEmail(
      undefined,
      "alice@example.com",
      "alerts@dmarc.mx",
      INPUT,
    );
    expect(outcome.sent).toBe(false);
    expect(outcome.reason).toBe("no_binding");
  });

  it("sends via the binding with the right envelope", async () => {
    const send = vi.fn().mockResolvedValue({ messageId: "m1" });
    const outcome = await sendAccountDeletedEmail(
      { send } as unknown as SendEmail,
      "alice@example.com",
      "alerts@dmarc.mx",
      INPUT,
    );
    expect(outcome.sent).toBe(true);
    expect(send).toHaveBeenCalledTimes(1);
    const arg = send.mock.calls[0][0] as {
      to: string;
      from: string;
      subject: string;
    };
    expect(arg.to).toBe("alice@example.com");
    expect(arg.from).toBe("alerts@dmarc.mx");
    expect(arg.subject).toMatch(/deleted/i);
  });

  it("captures a send failure as send_error rather than throwing", async () => {
    const send = vi.fn().mockRejectedValue(new Error("E_SENDER_NOT_VERIFIED"));
    const outcome = await sendAccountDeletedEmail(
      { send } as unknown as SendEmail,
      "alice@example.com",
      "alerts@dmarc.mx",
      INPUT,
    );
    expect(outcome.sent).toBe(false);
    expect(outcome.reason).toBe("send_error");
  });
});
