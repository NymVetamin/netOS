import { describeActionError } from "./describeActionError";

export function ActionError({ message }: { message: string }) {
  const error = describeActionError(message);
  return <section className="action-error">
    <div className="action-error-summary" role="alert">
      <span className="action-error-icon" aria-hidden="true">!</span>
      <div>
        <strong className="action-error-title">{error.title}</strong>
        {error.context && <div className="action-error-context">{error.context}</div>}
        <p>{error.reason}</p>
        <p className="action-error-hint">{error.hint}</p>
      </div>
    </div>
    <details className="action-error-details" key={message}>
      <summary>Технические подробности</summary>
      <pre tabIndex={0} aria-label="Полный текст ошибки">{message}</pre>
    </details>
  </section>;
}
