import { useState, useEffect } from "react";

export default function SearchBar({ onSearch, placeholder = "Search...", initialValue = "" }) {
  const [value, setValue] = useState(initialValue);

  useEffect(() => {
    setValue(initialValue);
  }, [initialValue]);

  const handleSubmit = (e) => {
    e.preventDefault();
    onSearch(value);
  };

  const handleClear = () => {
    setValue("");
    onSearch("");
  };

  return (
    <form onSubmit={handleSubmit} className="flex gap-2">
      <div className="relative flex-1">
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={placeholder}
          className="w-full px-3 py-2 bg-[#0f0f23] border border-[#2a2a4a] rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#38BDF8]/50"
        />
        {value && (
          <button
            type="button"
            onClick={handleClear}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-600 hover:text-gray-300"
          >
            &times;
          </button>
        )}
      </div>
      <button
        type="submit"
        className="px-4 py-2 bg-[#1a1a2e] border border-[#2a2a4a] rounded text-sm text-gray-300 hover:text-white hover:border-[#38BDF8]/40"
      >
        Search
      </button>
    </form>
  );
}
