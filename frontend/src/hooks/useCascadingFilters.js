import { useState, useEffect, useCallback, useRef } from "react";
import api from "../api/axios";

/**
 * Hook for interconnected cascading filters.
 *
 * When an upstream filter changes, all downstream filters reset and
 * available options are refetched from the backend with current filters applied.
 *
 * @param {string} endpoint - API endpoint for filter options (e.g., "/api/cves/filter-options")
 * @param {string[]} filterOrder - Ordered filter keys (e.g., ["source", "severity", "exploit_available"])
 * @param {Object} initialFilters - Initial filter values (e.g., from URL search params)
 */
export default function useCascadingFilters(endpoint, filterOrder, externalFilters = {}) {
  const [filters, setFilters] = useState(externalFilters);
  const [options, setOptions] = useState({});
  const [loading, setLoading] = useState(false);
  const debounceRef = useRef(null);

  // Sync internal filters when external filter state changes
  const extKey = JSON.stringify(externalFilters);
  const extRef = useRef(extKey);
  useEffect(() => {
    if (extRef.current !== extKey) {
      extRef.current = extKey;
      setFilters(externalFilters);
    }
  }, [extKey, externalFilters]);

  const fetchOptions = useCallback(async (currentFilters) => {
    try {
      setLoading(true);
      const params = {};
      for (const [key, val] of Object.entries(currentFilters)) {
        if (val !== "" && val !== undefined && val !== null) {
          params[key] = val;
        }
      }
      const res = await api.get(endpoint, { params });
      setOptions(res.data || {});
    } catch {
      // Keep existing options on error
    } finally {
      setLoading(false);
    }
  }, [endpoint]);

  // Fetch options whenever filters change
  useEffect(() => {
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchOptions(filters), 200);
    return () => clearTimeout(debounceRef.current);
  }, [filters, fetchOptions]);

  // Set a single filter — clears all downstream filters
  const setFilter = useCallback((key, value) => {
    setFilters((prev) => {
      const next = { ...prev, [key]: value };
      const keyIdx = filterOrder.indexOf(key);
      if (keyIdx >= 0) {
        // Clear all downstream filters
        for (let i = keyIdx + 1; i < filterOrder.length; i++) {
          next[filterOrder[i]] = "";
        }
      }
      return next;
    });
  }, [filterOrder]);

  const clearFilters = useCallback(() => {
    const empty = {};
    filterOrder.forEach((k) => { empty[k] = ""; });
    setFilters(empty);
  }, [filterOrder]);

  return { filters, options, setFilter, clearFilters, loading };
}
