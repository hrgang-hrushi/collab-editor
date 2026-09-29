import { LocalDaemonClient } from "@crux/daemon";

export class StreamSyncer {
  timeout = 5000;
  daemon = new LocalDaemonClient({ port: 7447 });

  async acquireLock(channel = "stream-mesh-primary") {
    console.log(`[StreamSyncer] Requesting mutual exclusion lock for: ${channel}...`);
    const ticket = await this.daemon.acquireLock(channel);
    console.log(`[StreamSyncer] Lock acquired successfully! Ticket: ${ticket.ticketId}`);
    return ticket;
  }
}

const syncer = new StreamSyncer();
syncer.acquireLock().then((ticket) => {
  console.log(`[StreamSyncer] Mesh channel ready on origin: ${ticket.origin}`);
});
