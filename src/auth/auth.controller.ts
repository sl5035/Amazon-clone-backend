import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { ExistingUserDto } from 'src/user/dtos/existing-user.dto';
import { NewUserDto } from 'src/user/dtos/new-user.dto';
import { UserDetails } from 'src/user/user-details.interface';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/register')
  register(@Body() newUserDto: NewUserDto): Promise<UserDetails | null> {
    return this.authService.register(newUserDto);
  }

  @Post('/login')
  @HttpCode(HttpStatus.OK)
  login(
    @Body() existingUserDto: ExistingUserDto,
  ): Promise<{ token: string } | null> {
    return this.authService.login(existingUserDto);
  }
}
