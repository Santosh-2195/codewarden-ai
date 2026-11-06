
export type TaskStatus = "To Do" | "In Progress" | "Done";

export type TaskComment = {
  id: number;
  author: string;
  text: string;
  createdAt: string;
};

export type Task = {
  id: number;
  title: string;
  description: string;
  status: TaskStatus;
  ownerId: number;
  comments: TaskComment[];
};

export type User = {
  id: number;
  name: string;
  email: string;
  role: "admin" | "member";
  bio: string;
};
