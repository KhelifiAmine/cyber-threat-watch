import { useState, useRef } from "react";

export default function HoverDetail({ children, content, delay = 200, position = "bottom" }) {
  const [visible, setVisible] = useState(false);
  const timeoutRef = useRef(null);

  const show = () => {
    timeoutRef.current = setTimeout(() => setVisible(true), delay);
  };

  const hide = () => {
    clearTimeout(timeoutRef.current);
    setVisible(false);
  };

  const posClass = position === "top"
    ? "bottom-full mb-2 left-1/2 -translate-x-1/2"
    : "top-full mt-2 left-1/2 -translate-x-1/2";

  return (
    <div className="relative inline-block" onMouseEnter={show} onMouseLeave={hide}>
      {children}
      {visible && (
        <div
          className={`absolute z-50 ${posClass} min-w-[200px] max-w-[320px] bg-[#1a1a2e] border border-[#2a2a4a] rounded-lg p-3 shadow-xl`}
        >
          {typeof content === "function" ? content() : content}
        </div>
      )}
    </div>
  );
}
