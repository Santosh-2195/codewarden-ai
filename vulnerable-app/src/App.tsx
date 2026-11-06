
import { useState } from "react";
import TaskComments from "./components/TaskComments";
import type { Task, TaskStatus, User } from "./types";
import "./App.css";

const initialUser: User = {
  id: 1,
  name: "Alex Johnson",
  email: "alex@example.com",
  role: "member",
  bio: "Frontend developer working on CDF projects.",
};

const initialTasks: Task[] = [
  {
    id: 1,
    title: "Design login page",
    description: "Create a basic login interface.",
    status: "Done",
    ownerId: 1,
    comments: [
      {
        id: 1,
        author: "Alex Johnson",
        text: "Initial design is complete.",
        createdAt: "2026-10-20",
      },
    ],
  },
  {
    id: 2,
    title: "Build project dashboard",
    description: "Display project tasks and status.",
    status: "In Progress",
    ownerId: 1,
    comments: [],
  },
  {
    id: 3,
    title: "Test application",
    description: "Verify that basic features work correctly.",
    status: "To Do",
    ownerId: 2,
    comments: [],
  },
];

function App() {
  const [user, setUser] = useState<User>(initialUser);
  const [tasks, setTasks] = useState<Task[]>(initialTasks);
  const [newTask, setNewTask] = useState("");
  const [activePage, setActivePage] = useState<
    "dashboard" | "profile"
  >("dashboard");
  const [selectedTaskId, setSelectedTaskId] =
    useState<number | null>(null);

  const [profileForm, setProfileForm] =
    useState<User>(initialUser);

  const selectedTask = tasks.find(
    (task) => task.id === selectedTaskId
  );

  function addTask() {
    const title = newTask.trim();

    if (!title) return;

    const task: Task = {
      id: Math.max(0, ...tasks.map((t) => t.id)) + 1,
      title,
      description: "New task",
      status: "To Do",
      ownerId: user.id,
      comments: [],
    };

    setTasks((currentTasks) => [...currentTasks, task]);
    setNewTask("");
  }

  function updateStatus(taskId: number) {
    const statuses: TaskStatus[] = [
      "To Do",
      "In Progress",
      "Done",
    ];

    setTasks((currentTasks) =>
      currentTasks.map((task) => {
        if (task.id !== taskId) return task;

        const currentIndex = statuses.indexOf(task.status);
        const nextStatus =
          statuses[(currentIndex + 1) % statuses.length];

        return {
          ...task,
          status: nextStatus,
        };
      })
    );
  }

  function addComment(taskId: number, text: string) {
    setTasks((currentTasks) =>
      currentTasks.map((task) => {
        if (task.id !== taskId) return task;

        const newComment = {
          id: Date.now(),
          author: user.name,
          text,
          createdAt: new Date().toLocaleDateString(),
        };

        return {
          ...task,
          comments: [...task.comments, newComment],
        };
      })
    );
  }

  function saveProfile(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setUser({ ...profileForm });
    alert("Demo profile updated successfully.");
  }

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>CDF TaskFlow</h1>
          <p>Simple Project & Task Management</p>
        </div>

        <nav className="navigation">
          <button
            className={
              activePage === "dashboard" ? "nav-active" : ""
            }
            onClick={() => setActivePage("dashboard")}
          >
            Dashboard
          </button>

          <button
            className={
              activePage === "profile" ? "nav-active" : ""
            }
            onClick={() => setActivePage("profile")}
          >
            My Profile
          </button>
        </nav>
      </header>

      <main className="container">
        {activePage === "dashboard" && (
          <section className="panel">
            <div className="section-heading">
              <div>
                <h2>Task Dashboard</h2>
                <p className="muted">
                  Manage your project tasks.
                </p>
              </div>
              <span className="task-counter">
                {tasks.length} Tasks
              </span>
            </div>

            <div className="add-task">
              <input
                type="text"
                placeholder="Enter a new task"
                value={newTask}
                onChange={(event) =>
                  setNewTask(event.target.value)
                }
                onKeyDown={(event) => {
                  if (event.key === "Enter") addTask();
                }}
              />

              <button onClick={addTask}>Add Task</button>
            </div>

            <div className="task-list">
              {tasks.map((task) => (
                <div className="task-card" key={task.id}>
                  <h3>{task.title}</h3>
                  <p>{task.description}</p>

                  <div className="task-footer">
                    <span className="status">
                      {task.status}
                    </span>

                    <div className="task-actions">
                      <button
                        className="secondary-button"
                        onClick={() =>
                          setSelectedTaskId(
                            selectedTaskId === task.id
                              ? null
                              : task.id
                          )
                        }
                      >
                        {selectedTaskId === task.id
                          ? "Hide Details"
                          : "View Details"}
                      </button>

                      <button
                        onClick={() => updateStatus(task.id)}
                      >
                        Change Status
                      </button>
                    </div>
                  </div>

                  {selectedTask?.id === task.id && (
                    <TaskComments
                      comments={task.comments}
                      onAddComment={(text) =>
                        addComment(task.id, text)
                      }
                    />
                  )}
                </div>
              ))}
            </div>
          </section>
        )}

        {activePage === "profile" && (
          <section className="panel profile-panel">
            <h2>My Profile</h2>

            <p className="muted">
              Manage your demo profile information.
            </p>

            <form
              className="profile-form"
              onSubmit={saveProfile}
            >
              <label htmlFor="profile-name">Full Name</label>
              <input
                id="profile-name"
                value={profileForm.name}
                onChange={(event) =>
                  setProfileForm({
                    ...profileForm,
                    name: event.target.value,
                  })
                }
              />

              <label htmlFor="profile-email">
                Email Address
              </label>
              <input
                id="profile-email"
                type="email"
                value={profileForm.email}
                onChange={(event) =>
                  setProfileForm({
                    ...profileForm,
                    email: event.target.value,
                  })
                }
              />

              <label htmlFor="profile-role">
                Account Role
              </label>
              <input
                id="profile-role"
                value={profileForm.role}
                disabled
              />

              <label htmlFor="profile-bio">
                Biography
              </label>
              <textarea
                id="profile-bio"
                rows={4}
                value={profileForm.bio}
                onChange={(event) =>
                  setProfileForm({
                    ...profileForm,
                    bio: event.target.value,
                  })
                }
              />

              <button type="submit">
                Save Profile
              </button>
            </form>
          </section>
        )}
      </main>

      <footer className="footer">
        CDF CyberSec Hackathon - Sample Application
      </footer>
    </div>
  );
}

export default App;
