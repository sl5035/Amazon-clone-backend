import { Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import { NewUserDto } from 'src/user/dtos/new-user.dto';
import { UserDetails } from 'src/user/user-details.interface';
import { ExistingUserDto } from 'src/user/dtos/existing-user.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private jwtService: JwtService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  async register(newUserDto: Readonly<NewUserDto>): Promise<UserDetails | any> {
    const { name, email, password } = newUserDto;

    const existingUser = await this.userService.findByEmail(email);
    if (existingUser) {
      return 'Email taken!';
    }

    const hashedPassword = await this.hashPassword(password);

    const newUser = await this.userService.create(name, email, hashedPassword);

    return this.userService._getUserDetails(newUser);
  }

  async doesPasswordsMatch(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  async validateUser(
    email: string,
    password: string,
  ): Promise<UserDetails | null> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      return null;
    }

    const doesPasswordsMatch = await this.doesPasswordsMatch(
      password,
      user.password,
    );
    if (!doesPasswordsMatch) {
      return null;
    }

    return this.userService._getUserDetails(user);
  }

  async login(
    existingUserDto: ExistingUserDto,
  ): Promise<{ token: string } | null> {
    const { email, password } = existingUserDto;
    const user = await this.validateUser(email, password);
    if (!user) {
      return null;
    }

    const jwt = await this.jwtService.signAsync({ user });

    return { token: jwt };
  }
}
