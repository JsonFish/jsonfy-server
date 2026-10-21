import {
  Injectable,
  BadRequestException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import axios from 'axios';
import * as nanoid from 'nanoid';

import { UserService } from '../user/user.service';
import { AuthorizedRequest } from './auth.controller';

import secretKey from '@/config/jwt.config';
import githubConfig from '@/config/github.config';
import getIpAddress from '@/utils/ip-address';

@Injectable()
export class AuthService {
  constructor(
    private JwtService: JwtService,
    private UserService: UserService,
  ) {}

  async refreshToken(request: AuthorizedRequest) {
    const { id, username } = request.user;

    return await this.generateToken(id, username);
  }

  async loginByGithub(body: { code: string }, ip: string | undefined) {
    const { code } = body;

    if (!githubConfig.client_id || !githubConfig.client_secret) {
      throw new ServiceUnavailableException(
        'GitHub 登录尚未配置，暂时无法使用',
      );
    }

    if (!code) throw new BadRequestException('登录失败，请稍后再试');

    // 获取 access_token
    const response = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        client_id: githubConfig.client_id,
        client_secret: githubConfig.client_secret,
        code,
      },
      {
        headers: {
          Accept: 'application/json',
        },
      },
    );

    if (!response?.data?.access_token) {
      throw new BadRequestException(response?.data?.error ?? 'GitHub 登录失败');
    }

    const userInfo = await axios.get('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${response.data.access_token}`,
        Accept: 'application/vnd.github+json',
      },
      timeout: 10_000,
    });

    return this.loginWithGithubUser(userInfo.data, ip);
  }

  async loginByGithubAccessToken(
    body: { accessToken: string },
    ip: string | undefined,
  ) {
    const accessToken =
      typeof body?.accessToken === 'string' ? body.accessToken.trim() : '';

    if (!accessToken || accessToken.length > 4096) {
      throw new BadRequestException('GitHub access token 无效');
    }

    if (!githubConfig.client_id || !githubConfig.client_secret) {
      throw new ServiceUnavailableException(
        'GitHub 登录尚未配置，暂时无法使用',
      );
    }

    try {
      // 验证 token 确实由本项目配置的 GitHub OAuth App 签发，避免接收其他应用的 token。
      const authorization = await axios.post(
        `https://api.github.com/applications/${encodeURIComponent(githubConfig.client_id)}/token`,
        { access_token: accessToken },
        {
          auth: {
            username: githubConfig.client_id,
            password: githubConfig.client_secret,
          },
          headers: {
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
          },
          timeout: 10_000,
        },
      );

      if (!authorization.data?.user?.id) {
        throw new UnauthorizedException('GitHub access token 无效');
      }

      const userInfo = await axios.get('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
        timeout: 10_000,
      });

      if (String(userInfo.data?.id) !== String(authorization.data.user.id)) {
        throw new UnauthorizedException('GitHub 用户验证失败');
      }

      return this.loginWithGithubUser(userInfo.data, ip);
    } catch (error) {
      if (
        error instanceof UnauthorizedException ||
        error instanceof BadRequestException ||
        error instanceof ServiceUnavailableException
      ) {
        throw error;
      }

      if (axios.isAxiosError(error) && error.response?.status === 401) {
        throw new UnauthorizedException('GitHub access token 无效');
      }

      if (axios.isAxiosError(error) && error.response?.status === 404) {
        throw new UnauthorizedException('GitHub access token 不属于当前应用');
      }

      throw new ServiceUnavailableException('暂时无法验证 GitHub 登录');
    }
  }

  private async loginWithGithubUser(
    profile: {
      id?: string | number;
      login?: string;
      name?: string | null;
      avatar_url?: string;
      email?: string | null;
    },
    ip: string | undefined,
  ) {
    if (profile?.id === undefined || profile?.id === null) {
      throw new BadRequestException('获取 GitHub 用户信息失败');
    }

    const ipData = await getIpAddress(ip).catch(() => ({
      ip: ip ?? '-',
      country: '-',
      province: '-',
      city: '-',
    }));
    const githubUserInfo = {
      avatar: profile.avatar_url ?? '',
      username: (
        profile.name?.trim() ||
        profile.login?.trim() ||
        String(profile.id)
      ).slice(0, 50),
      email: profile.email?.trim() || '-',
      ip: ipData.ip,
      ipAddress: ipData.province,
      githubId: String(profile.id),
    };
    const result = await this.UserService.findAll({
      githubId: githubUserInfo.githubId,
    });

    if (result.length !== 0) {
      const existingUser = result[0];
      const id = existingUser.id;
      const role = existingUser.role;
      await this.UserService.updateUser({ ...githubUserInfo, id, role });
      await this.UserService.updateLoginInfo(id, ipData.ip, ipData.province);

      const { accessToken, refreshToken } = await this.generateToken(
        id,
        githubUserInfo.username,
      );

      return {
        id,
        avatar: githubUserInfo.avatar,
        username: githubUserInfo.username,
        role,
        accessToken,
        refreshToken,
      };
    }

    const id = nanoid.customAlphabet('1234567890', 10)();
    await this.UserService.addUserByGithub({
      ...githubUserInfo,
      id,
      lastLoginTime: new Date(),
      lastLoginIp: ipData.ip,
      lastLoginAddress: ipData.province,
      loginCount: 1,
    });

    const { accessToken, refreshToken } = await this.generateToken(
      id,
      githubUserInfo.username,
    );

    return {
      id,
      avatar: githubUserInfo.avatar,
      username: githubUserInfo.username,
      role: 0,
      accessToken,
      refreshToken,
    };
  }

  private async generateToken(id: string | number, username: string) {
    const accessToken = await this.JwtService.signAsync(
      { id, username },
      { expiresIn: '1h', secret: secretKey.accessSecretKey },
    );
    const refreshToken = this.JwtService.sign(
      { id, username },
      { expiresIn: '1d', secret: secretKey.refreshSecretKey },
    );

    return { accessToken, refreshToken };
  }
}
