import { motion } from 'motion/react';
import { Lock, Unlock } from 'lucide-react';
import { useState, useEffect } from 'react';

export default function AnimatedLock() {
  return (
    <div className="relative w-5 h-5 flex items-center justify-center text-emerald-500">
      <motion.div
        animate={{ 
          y: [0, -3, 3, 0],
          x: [-2, 2, -2, 2, 0],
          rotate: [0, 5, -5, 0]
        }}
        transition={{ 
          duration: 15, // Extremely slow water-flow like movement
          repeat: Infinity,
          ease: "linear" // Linear for smoother continuous flow
        }}
        className="flex items-center justify-center"
      >
        <motion.div
          animate={{ 
            scale: [1, 1.15, 1],
          }}
          transition={{ 
            duration: 6, // Even slower motion pulse
            repeat: Infinity,
            ease: "easeInOut"
          }}
        >
          <motion.div
            initial={{ opacity: 1 }}
            animate={{ opacity: [1, 0, 1] }}
            transition={{ 
              duration: 5, // Very slow lock/unlock
              repeat: Infinity,
              repeatDelay: 4,
              ease: "easeInOut"
            }}
            className="absolute inset-0 flex items-center justify-center"
          >
            <Lock size={18} />
          </motion.div>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: [0, 1, 0] }}
            transition={{ 
              duration: 5, // Very slow lock/unlock
              repeat: Infinity,
              repeatDelay: 4,
              ease: "easeInOut"
            }}
            className="absolute inset-0 flex items-center justify-center"
          >
            <Unlock size={18} />
          </motion.div>
        </motion.div>
      </motion.div>
    </div>
  );
}
