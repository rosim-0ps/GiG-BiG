import { motion, useMotionValue, useTransform, animate } from "motion/react";
import { useEffect, useState } from "react";

export default function TypewriterText({ text, delay = 0 }: { text: string; delay?: number }) {
  const count = useMotionValue(0);
  const rounded = useTransform(count, (latest) => Math.round(latest));
  const displayText = useTransform(rounded, (latest) => text.slice(0, latest));
  const [done, setDone] = useState(false);

  useEffect(() => {
    const controls = animate(count, text.length, {
      type: "tween",
      duration: 3, // Slow motion typing
      ease: "easeInOut",
      delay: delay,
      onComplete: () => setDone(true),
    });
    return controls.stop;
  }, [count, text.length, delay]);

  return (
    <span className="relative">
      <motion.span>{displayText}</motion.span>
      {!done && (
        <motion.span
          animate={{ opacity: [0, 1, 0] }}
          transition={{ repeat: Infinity, duration: 0.8 }}
          className="inline-block w-0.5 h-4 bg-emerald-500 ml-0.5 align-middle"
        />
      )}
    </span>
  );
}
