import { Thread } from "../components/thread";

/** The account-wide thread with the agent (src/chat.ts): the team asking about the account as a whole. */
export default function Chat() {
  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold text-zinc-100">Chat with the advisor</h1>
      <p className="mb-4 text-sm text-zinc-400">One thread for the team. Each message goes to the agent with today's observation, the open recommendations and the last twelve messages; it reads the advisor's facts with its tools before it answers. For one recommendation's plan, use the thread under that recommendation.</p>
      <Thread recId={null} title="The account" hint="the agent sees today's observation, the open recommendations and this thread" tall />
    </div>
  );
}
