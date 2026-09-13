import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

export default function AnimatedButton({ 
  children, 
  className = '', 
  onClick, 
  style = {},
  variant = 'default', // 'primary', 'danger', 'ghost', 'none'
  active = false,
  ...props 
}) {
  const [ripples, setRipples] = useState([]);

  const handleClick = (e) => {
    // Calculate ripple position relative to the button
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    const newRipple = { x, y, id: Date.now() };
    setRipples((prev) => [...prev, newRipple]);
    
    // Remove ripple after animation
    setTimeout(() => {
      setRipples((prev) => prev.filter((r) => r.id !== newRipple.id));
    }, 600);

    if (onClick) onClick(e);
  };

  // Determine base styles based on variant
  let baseClass = className;
  if (!className.includes('header-btn') && variant !== 'none') {
     if (variant === 'primary') baseClass += ' header-btn primary';
     else if (variant === 'default') baseClass += ' header-btn';
  }

  // Prevent CSS transition: all from lagging Framer Motion's transform/box-shadow physics
  const safeStyle = { ...style, position: 'relative', overflow: 'hidden' };
  if (safeStyle.transition && typeof safeStyle.transition === 'string' && safeStyle.transition.includes('all')) {
    const durationMatch = safeStyle.transition.match(/(\d+\.?\d*m?s)/);
    const duration = durationMatch ? durationMatch[0] : '0.2s';
    safeStyle.transition = `color ${duration}, background-color ${duration}, border-color ${duration}, opacity ${duration}, fill ${duration}, stroke ${duration}`;
  }

  return (
    <motion.button
      className={baseClass}
      style={safeStyle}
      onClick={handleClick}
      animate={active ? { backgroundColor: 'rgba(0, 163, 255, 0.12)', scale: 1.015, y: -1, boxShadow: '0 2px 8px rgba(0, 163, 255, 0.1)' } : { scale: 1, y: 0, boxShadow: '0 0px 0px rgba(0,0,0,0), inset 0 0 0px rgba(0,0,0,0)', backgroundColor: style.background || 'transparent' }}
      whileHover={{ scale: 1.03, y: -1, boxShadow: '0 5px 15px rgba(0, 163, 255, 0.25)' }}
      whileTap={{ scale: 0.95 }}
      transition={{ type: 'spring', stiffness: 400, damping: 17 }}
      {...props}
    >
      {/* Ripples */}
      <AnimatePresence>
        {ripples.map((r) => (
          <motion.span
            key={r.id}
            initial={{ scale: 0, opacity: 0.5 }}
            animate={{ scale: 4, opacity: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.6, ease: 'easeOut' }}
            style={{
              position: 'absolute',
              top: r.y,
              left: r.x,
              width: 50,
              height: 50,
              background: 'rgba(255, 255, 255, 0.3)',
              borderRadius: '50%',
              transform: 'translate(-50%, -50%)',
              pointerEvents: 'none',
              zIndex: 0
            }}
          />
        ))}
      </AnimatePresence>
      <span style={{ zIndex: 1, display: 'flex', alignItems: 'center', gap: 'inherit', width: '100%', justifyContent: 'inherit' }}>
        {children}
      </span>
    </motion.button>
  );
}
