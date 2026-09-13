import { motion } from 'framer-motion';

export const StaggeredList = ({ children, className = '', delay = 0.05, component = 'div', ...props }) => {
  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: delay, delayChildren: 0.1 }
    }
  };

  const MotionComponent = motion[component] || motion.div;

  return (
    <MotionComponent
      className={className}
      variants={containerVariants}
      initial="hidden"
      animate="show"
      exit="hidden"
      {...props}
    >
      {children}
    </MotionComponent>
  );
};

export const StaggeredItem = ({ children, className = '', component = 'div', style = {}, ...props }) => {
  const itemVariants = {
    hidden: { opacity: 0, x: -10, y: 10 },
    show: { 
      opacity: 1, 
      x: 0, 
      y: 0, 
      transition: { type: 'spring', stiffness: 300, damping: 24 } 
    },
    exit: { opacity: 0, scale: 0.9, transition: { duration: 0.2 } }
  };

  const MotionComponent = motion[component] || motion.div;

  return (
    <MotionComponent
      className={className}
      variants={itemVariants}
      style={{ ...style, willChange: 'transform, opacity' }}
      {...props}
    >
      {children}
    </MotionComponent>
  );
};
