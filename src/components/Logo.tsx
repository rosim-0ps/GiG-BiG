import { motion } from 'motion/react';

interface LogoProps {
  className?: string;
  size?: 'sm' | 'lg';
}

export default function Logo({ className = '', size = 'lg' }: LogoProps) {
  const containerVariants = {
    animate: {
      transition: {
        staggerChildren: 0.4,
        repeat: Infinity,
        repeatType: "reverse" as const,
        repeatDelay: 1
      }
    }
  };

  const letterVariants = {
    initial: { opacity: 0, y: 10, scale: 0.8 },
    animate: { 
      opacity: 1, 
      y: 0, 
      scale: 1,
      transition: {
        type: "spring",
        stiffness: 200,
        damping: 10
      }
    }
  };

  const dotVariants = {
    initial: { scale: 0 },
    animate: { 
      scale: [0, 1.5, 1],
      transition: {
        times: [0, 0.5, 1],
        duration: 0.6
      }
    }
  };

  const isLarge = size === 'lg';

  return (
    <motion.div 
      className={`flex items-center justify-center gap-1 font-black tracking-tighter select-none ${className}`}
      variants={containerVariants}
      initial="initial"
      animate="animate"
    >
      {/* First G */}
      <motion.span 
        variants={letterVariants}
        className={isLarge ? "text-4xl" : "text-xl"}
      >
        G
      </motion.span>

      {/* i */}
      <motion.div 
        variants={letterVariants}
        className="relative flex flex-col items-center"
      >
        <motion.div 
          variants={dotVariants}
          className={`bg-emerald-500 rounded-full ${isLarge ? "w-2 h-2 mb-1" : "w-1 h-1 mb-0.5"}`}
        />
        <span className={isLarge ? "text-4xl leading-[0.8]" : "text-xl leading-[0.8]"}>
          i
        </span>
      </motion.div>

      {/* Second G */}
      <motion.span 
        variants={letterVariants}
        className={isLarge ? "text-4xl" : "text-xl"}
      >
        G
      </motion.span>
    </motion.div>
  );
}
