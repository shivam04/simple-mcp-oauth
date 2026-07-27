import "express-session";

declare module "express-session" {
  interface SessionData {
    userId?: string;
    oauth?: {
      client_id: string;
      redirect_uri: string;
      response_type: string;
      code_challenge?: string;
      state?: string;
      scope?: string;
    };
  }
}