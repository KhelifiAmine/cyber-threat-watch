import { useState, useEffect, useRef } from "react";

/**
 * In-app modal replacing window.confirm and window.prompt.
 *
 * Props:
 *   message      – main body text
 *   confirmLabel – text for the confirm button (default "Confirm")
 *   cancelLabel  – text for the cancel button (default "Cancel")
 *   danger       – if true, confirm button is red (destructive action)
 *   withInput    – if true, shows a textarea for optional user input
 *   inputLabel   – label above the textarea
 *   inputPlaceholder
 *   onConfirm(value) – called with textarea value (or "" if withInput=false)
 *   onCancel     – called when cancelled
 */
export default function ConfirmModal({
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  danger = false,
  withInput = false,
  inputLabel = "",
  inputPlaceholder = "",
  onConfirm,
  onCancel,
}) {
  const [value, setValue] = useState("");
  const inputRef = useRef(null);

  useEffect(() => {
    if (withInput && inputRef.current) inputRef.current.focus();
  }, [withInput]);

  const handleConfirm = () => onConfirm(value);

  const handleKey = (e) => {
    if (e.key === "Escape") onCancel();
    if (e.key === "Enter" && !withInput) handleConfirm();
  };

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
      onClick={onCancel}
      onKeyDown={handleKey}
      tabIndex={-1}
    >
      <div
        className="bg-[#12121e] border border-[#2a2a4a] rounded-lg p-5 w-full max-w-sm shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <p className="text-sm text-gray-200 leading-snug mb-4">{message}</p>

        {withInput && (
          <div className="mb-4">
            {inputLabel && (
              <label className="text-[10px] uppercase text-gray-500 mb-1 block">{inputLabel}</label>
            )}
            <textarea
              ref={inputRef}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={inputPlaceholder}
              rows={3}
              className="w-full bg-[#0f0f23] border border-[#2a2a4a] rounded p-2 text-xs text-gray-200 focus:outline-none focus:border-[#38BDF8]/50 resize-none"
            />
          </div>
        )}

        <div className="flex gap-2 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-xs rounded bg-[#1a1a2e] border border-[#2a2a4a] text-gray-400 hover:text-gray-200"
          >
            {cancelLabel}
          </button>
          <button
            onClick={handleConfirm}
            className={`px-4 py-2 text-xs rounded border ${
              danger
                ? "bg-red-900/20 border-red-700/50 text-red-400 hover:bg-red-900/40"
                : "bg-[#38BDF8]/10 border-[#38BDF8]/40 text-[#38BDF8] hover:bg-[#38BDF8]/20"
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
