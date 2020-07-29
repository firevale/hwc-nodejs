import { Signer, SigningHttpRequest } from './signer';
import { request } from 'https';

const ENDPOINT = 'cdn.myhuaweicloud.com';

export type TaskStatus = 'task_done' | 'task_inprocess';
export type TaskType = 'refresh' | 'preheating';
export type RefreshType = 'file' | 'directory';

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

export class CdnClient {
  private signer: Signer;

  constructor(ak: string, sk: string) {
    this.signer = new Signer(ak, sk);
  }

  private request<T>(apiName: string, params: any): Promise<T> {
    const body = JSON.stringify(params);

    const url = `https://${ENDPOINT}/v1.0/cdn/${apiName}?enterprise_project_id=ALL`;

    const r = new SigningHttpRequest('POST', url, { 'Content-Type': 'application/json' }, body);

    const opts = this.signer.sign(r);

    return new Promise((resolve, reject) => {
      const req = request(opts, (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data) as T);
          } else {
            reject(data);
          }
        });
      });
      req.on('error', (err) => reject(err));
      req.write(r.body);
      req.end();
    });
  }

  public async refreshUrls(urls: Array<string>, type?: RefreshType): Promise<RefreshTaskResponse> {
    const res = await this.request<RefreshTaskResponse>('refreshtasks', { refreshTask: { type, urls } });
    return res;
  }

  public async preheatUrls(urls: Array<string>): Promise<PreheatTaskResponse> {
    const res = await this.request<PreheatTaskResponse>('preheatingtasks', { preheatingTask: { urls } });
    return res;
  }
}
