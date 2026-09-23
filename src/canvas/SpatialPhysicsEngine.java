/**
 * Physics-based 120Hz smooth cursor lerping engine.
 * Damped harmonic oscillation prevents discrete step jumping.
 */
export public class SpatialPhysicsEngine {
  private stiffness = 340;
  private damping = 30;

  calculateNextPosition(
    curr: { x: number; y: number },
    target: { x: number; y: number },
    vel: { x: number; y: number },
    dt: number
  ) {
    const ax = (target.x - curr.x) * this.stiffness - vel.x * this.damping;
    const ay = (target.y - curr.y) * this.stiffness - vel.y * this.damping;

    const nextVx = vel.x + ax * dt;
    const nextVy = vel.y + ay * dt;

    return {
      pos: { x: curr.x + nextVx * dt, y: curr.y + nextVy * dt },
      vel: { x: nextVx, y: nextVy },
    };
  }
}

const engine = new SpatialPhysicsEngine();
const step = engine.calculateNextPosition({ x: 0, y: 0 }, { x: 100, y: 100 }, { x: 0, y: 0 }, 0.016);
console.log(`[SpatialPhysicsEngine] 120Hz lerp initialized. Next vector: (${step.pos.x.toFixed(2)}, ${step.pos.y.toFixed(2)})`);
