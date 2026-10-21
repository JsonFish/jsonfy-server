import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';

const sensitiveFieldNames = new Set([
  'access_token',
  'accesstoken',
  'refresh_token',
  'refreshtoken',
  'token',
  'client_secret',
  'clientsecret',
  'password',
]);

function redactSensitiveFields(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSensitiveFields);
  if (!value || typeof value !== 'object') return value;

  return Object.fromEntries(
    Object.entries(value).map(([key, fieldValue]) => [
      key,
      sensitiveFieldNames.has(key.toLowerCase())
        ? '[REDACTED]'
        : redactSensitiveFields(fieldValue),
    ]),
  );
}

@Catch()
export class AllExceptionFilter implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: HttpException, host: ArgumentsHost) {
    const errorMessage = exception.message;

    const { httpAdapter } = this.httpAdapterHost;
    const ctx = host.switchToHttp();
    const request = ctx.getRequest();
    const response = ctx.getResponse();

    // 获取 HTTP 状态码，若无法获取则默认设置为 INTERNAL_SERVER_ERROR
    const httpStatus =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const responseBody = {
      code: httpStatus,
      message: errorMessage,
      data: {
        query: redactSensitiveFields(request.query),
        body: redactSensitiveFields(request.body),
        params: redactSensitiveFields(request.params),
        method: request.method,
        url: request.url,
      },
    };

    httpAdapter.reply(response, responseBody, httpStatus);
  }
}
