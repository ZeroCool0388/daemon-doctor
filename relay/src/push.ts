// Hook is the phone push call. NoopPush does not call a network and holds no keys.
export interface Hook {
  deliver(macID: string, alertID: string, message: string): Promise<void>;
}

export class NoopPush implements Hook {
  async deliver(_macID: string, _alertID: string, _message: string): Promise<void> {}
}
