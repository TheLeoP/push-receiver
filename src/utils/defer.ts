export default function defer<T>(): {
  promise: Promise<T | undefined>;
  resolve: (value?: T | PromiseLike<T>) => void;
  reject: (reason?: any) => void;
  isResolved: boolean;
} {
  let resolve: (value?: T | PromiseLike<T>) => void;
  let reject: (reason?: any) => void;
  let isResolved = false;

  const promise = new Promise<T | undefined>((res, rej) => {
    resolve = (value?: T | PromiseLike<T>) => {
      isResolved = true;
      res(value);
    };
    reject = (reason?: any) => {
      isResolved = true;
      rej(reason);
    };
  });

  // @ts-ignore: both `resolve` and `reject` are initialized synchronously in
  // the Promise constructor
  return { promise, resolve, reject, isResolved };
}
