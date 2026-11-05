export * from './auth';
export * from './forum';

export type Theme = 'system' | 'light' | 'dark';

export type PageinationData = {
  total: number;
  page: number;
  pageSize: number;
};
