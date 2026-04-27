import { createContext, useCallback, useContext, useMemo, useState } from "react";

export type AssistantSignal = {
  path: string;
  severity: "warning" | "info";
  title: string;
  message: string;
  badgeCount?: number;
  prompts?: string[];
};

type AssistantSignalContextValue = {
  signal: AssistantSignal | null;
  setSignal: (signal: AssistantSignal | null) => void;
  clearSignal: (path?: string) => void;
};

const AssistantSignalContext = createContext<AssistantSignalContextValue | null>(null);

export function AssistantSignalProvider({ children }: { children: React.ReactNode }) {
  const [signal, setSignalState] = useState<AssistantSignal | null>(null);
  const setSignal = useCallback((nextSignal: AssistantSignal | null) => {
    setSignalState(nextSignal);
  }, []);
  const clearSignal = useCallback((path?: string) => {
    setSignalState((current) => {
      if (!path) {
        return null;
      }

      return current?.path === path ? null : current;
    });
  }, []);

  const value = useMemo<AssistantSignalContextValue>(
    () => ({
      signal,
      setSignal,
      clearSignal,
    }),
    [clearSignal, setSignal, signal],
  );

  return (
    <AssistantSignalContext.Provider value={value}>{children}</AssistantSignalContext.Provider>
  );
}

export function useAssistantSignal() {
  const context = useContext(AssistantSignalContext);
  if (!context) {
    throw new Error("useAssistantSignal must be used inside AssistantSignalProvider.");
  }

  return context;
}
