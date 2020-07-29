export declare type TaskStatus = 'task_done' | 'task_inprocess';
export declare type TaskType = 'refresh' | 'preheating';
export declare type RefreshType = 'file' | 'directory';
export interface TaskInfo {
    id: string;
    task_type: TaskType;
    status: TaskStatus;
    processing: number;
    succeed: number;
    failed: number;
    total: number;
    create_time: number;
    urls: string[];
}
export interface RefreshTaskResponse {
    refreshTask: TaskInfo;
}
export interface PreheatTaskResponse {
    preheatingTask: TaskInfo;
}
export declare class CdnClient {
    private signer;
    constructor(ak: string, sk: string);
    private request;
    refreshUrls(urls: Array<string>, type?: RefreshType): Promise<RefreshTaskResponse>;
    preheatUrls(urls: Array<string>): Promise<PreheatTaskResponse>;
}
