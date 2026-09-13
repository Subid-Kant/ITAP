import { motion } from 'framer-motion';

export default function HoverCard({ children, className = 'panel', style = {}, tiltFactor, ...props }) {
  return (
    <motion.div
      className={className}
      style={{
        ...style,
        position: 'relative',
        willChange: 'transform'
      }}
      whileHover={{ scale: 1.01, boxShadow: '0 20px 40px rgba(0,0,0,0.4)', borderColor: 'rgba(0, 163, 255, 0.4)' }}
      transition={{ type: 'spring', stiffness: 300, damping: 20 }}
      {...props}
    >
      <div style={{ height: '100%' }}>
        {children}
      </div>
    </motion.div>
  );
}
