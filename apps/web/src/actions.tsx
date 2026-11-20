import { createContext, useContext } from "react";
import type { Alert } from "./lib";

/** What any alert view can ask the shell to do, without threading callbacks through every page. */
export type Actions = {
  replay?: (a: Alert) => void;
  canReplay?: (a: Alert) => boolean;
};

export const ActionsContext = createContext<Actions>({});
export const useActions = () => useContext(ActionsContext);
