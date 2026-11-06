import { useEffect, useRef } from "react";
import DOMPurify from "dompurify";

export function NoteBody({ note }) {
  const ref = useRef(null);
  useEffect(() => {
    ref.current.innerHTML = note.body;
  }, [note.body]);
  return <div ref={ref} />;
}

export function SafePreview({ note }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(note.body) }} />;
}

export function PlainTitle({ note }) {
  return <h2>{note.title}</h2>;
}

export function saveSession(token) {
  localStorage.setItem("authToken", token);
}
