
import { useState } from "react";
import type { TaskComment } from "../types";

type Props = {
  comments: TaskComment[];
  onAddComment: (text: string) => void;
};

export default function TaskComments({
  comments,
  onAddComment,
}: Props) {
  const [commentText, setCommentText] = useState("");

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const text = commentText.trim();

    if (!text) return;

    onAddComment(text);
    setCommentText("");
  }

  return (
    <div className="comments-section">
      <h4>Comments</h4>

      {comments.length === 0 ? (
        <p className="muted">No comments yet.</p>
      ) : (
        <div className="comments-list">
          {comments.map((comment) => (
            <div className="comment" key={comment.id}>
              <strong>{comment.author}</strong>

              <div
                dangerouslySetInnerHTML={{
                  __html: comment.text,
                }}
              />

              <small>{comment.createdAt}</small>
            </div>
          ))}
        </div>
      )}

      <form className="comment-form" onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Write a comment..."
          value={commentText}
          onChange={(event) => setCommentText(event.target.value)}
        />

        <button type="submit">Add Comment</button>
      </form>
    </div>
  );
}
