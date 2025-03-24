import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';

import * as bcrypt from 'bcrypt';

import { LoginUserDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('AuthService');

    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async registerUser(registerUserDto: RegisterUserDto) {

        const { email, password, name } = registerUserDto;

        try {
            const user = await this.user.findUnique({
                where: {
                    email
                }
            });

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    password: bcrypt.hashSync(password, 10),
                    name
                }
            });

            const { password: _, ...rest } = newUser;

            return {
                user: rest,
                token: 'token'
            }

        } catch (err) {
            throw new RpcException({
                status: 400,
                message: err.message
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {

        const { email, password } = loginUserDto;

        try {
            const user = await this.user.findUnique({
                where: { email }
            });

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password is incorrect'
                });
            }

            const isPasswordMatch = bcrypt.compareSync(password, user.password);

            if (!isPasswordMatch) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password is incorrect'
                });
            }

            const { password: _, ...rest } = user;

            return {
                user: rest,
                token: 'token'
            }

        } catch (err) {
            throw new RpcException({
                status: 400,
                message: err.message
            });
        }
    }

}
