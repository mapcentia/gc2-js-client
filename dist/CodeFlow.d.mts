import { O as Options, G as Gc2Service } from './gc2.services-BGKfkyyU.mjs';
import 'axios';

declare class CodeFlow {
    options: Options;
    service: Gc2Service;
    constructor(options: Options);
    redirectHandle(): Promise<boolean | string>;
    signin(): Promise<void>;
}

export { CodeFlow as default };
