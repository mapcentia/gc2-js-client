declare class Sql {
    constructor();
    select(query: string): Promise<any>;
}

export { Sql as default };
