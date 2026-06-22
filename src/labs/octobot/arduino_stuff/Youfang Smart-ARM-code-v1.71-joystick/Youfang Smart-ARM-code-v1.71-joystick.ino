/*

  somebot ARM
  JoyStick Control for UNO/NANO Board

  pins:
  11 : Servo base   底座舵机
  10 : Servo left   左臂舵机
  9 : Servo right  右臂舵机
  5 : Servo claw   爪子舵机

*/

#include <Servo.h>


#define SERVOS      (4)     // 机械臂需要的舵机个数

Servo arm_servos[SERVOS];   // 声明SERVOS个舵机
/*
  arm_servos[0]: pin 11 -- Servo base   底座舵机
  arm_servos[1]: pin 10 -- Servo left   左臂舵机
  arm_servos[2]: pin  9 -- Servo right  右臂舵机
  arm_servos[3]: pin  5 -- Servo claw   爪子舵机
*/
int servo_pins[SERVOS];         // 舵机要接入的主板IO口
int servo_cur_angle[SERVOS];    // 舵机当前的旋转角度
int servo_min_angle[SERVOS];    // 允许舵机旋转到达的最小值
int servo_max_angle[SERVOS];    // 允许舵机旋转到达的最大值
int servo_init_angle[SERVOS];   // 刚上电时，舵机的初始角度

/*
  joystick_value 存储摇杆ADC值；
  每个摇杆实际上是2个电位器，摇杆左右推会旋转1个电位器，前后推会旋转另外1个电位器；
  电位器: 即滑动变阻器，通过旋转、滑动触点，改变输出电压；
  程序将使用arduino的Analog Pin读取电位器的电压值，读取出来的原始ADC值范围是0--1024；
  A0 --> joystick_value[0] --> 左摇杆左右推，控制底座舵机旋转；
  A1 --> joystick_value[1] --> 左摇杆前后推，控制左臂舵机旋转；
  A2 --> joystick_value[2] --> 右摇杆前后推，控制右臂舵机旋转；
  A3 --> joystick_value[3] --> 右摇杆左右推，控制爪子舵机旋转；

  ------------------------------ 示意图 --------------------------------

               A1=0                                A2=0
                ^                                   ^
                |                                   |
             ______                              ______
            |      |                            |      |
   A0=0 <-- | 左摇杆| --> A0=1024       A3=0 <-- | 右摇杆| --> A3=1024
            |______|                            |______|
                |                                   |
               \ /                                 \ /
              A1=1024                             A2=1024

*/
int joystick_value[SERVOS];
#define JOYSTICK_MIN_THRESH     (300)   // 摇杆ADC值的最小阈值，用于判断摇杆向哪边推动了
#define JOYSTICK_MAX_THRESH     (700)   // 摇杆ADC值的最大阈值，用于判断摇杆向哪边推动了

#define CLAW_OPEN_ANGLE     (20)    // 爪子张开时的舵机角度
#define CLAW_CLOSE_ANGLE    (0)    // 爪子闭合时的舵机角度
#define CLAW_SERVO_INDEX    (SERVOS-1)  // 爪子舵机的序号，倒数第一个

#define LEARN_MAX_ACTIONS   (100)   // 学习模式最多可记录的动作个数
/*
    机械臂动作学习模式操作步骤：
    1、按住遥杆左键，再按一下arduino重启按钮或者关机重启，遥杆板指示灯灭说明加入录制状态；
    2、通过遥杆控制机械臂状态，到达指定位置，按一下遥杆左键，记录当前状态，依次操作；
    3、按一下遥杆右键，结束录制，机械臂自动循环地执行之前记录学习的动作；
    4、再次按遥杆左键，停止自动循环，进入摇杆操控模式。
    注意：所记录的动作重启或关机后会消失，重新录制会覆盖之前的动作。
*/
bool learning_mode = false;  // 是否进入学习模式？
bool repeat_mode = false;  // 是否重复刚才学习到的动作？(配合学习模式使用)

int learn_actions[LEARN_MAX_ACTIONS][SERVOS];   // 学习模式存储记录动作
int learn_action_count = 0;                     // 学习模式记录了多少动作？


bool play_demo_mode = false;  // 是否自动播放执行预设的一组动作序列？ 即下面的 demo_actions

#define ANGLE_REPORT_MS 250   // [OctoBot] report actual servo angles to the Pi every N ms
unsigned long last_angle_report = 0;

// demo_actions属于预设的动作序列，要根据您自己需求做调整，下面只是范例。
int demo_actions[9][SERVOS] = {
  { 90,  55, 165, CLAW_CLOSE_ANGLE},
  { 45, 145,  90,  CLAW_OPEN_ANGLE},
  { 90,  55, 165,  CLAW_CLOSE_ANGLE},
  {135, 145,  90, CLAW_OPEN_ANGLE},
  { 90,  55, 165, CLAW_CLOSE_ANGLE},
  {135, 145,  90,  CLAW_OPEN_ANGLE},
  { 90,  55, 165,  CLAW_CLOSE_ANGLE},
  { 45, 145,  90, CLAW_OPEN_ANGLE},
  { 90,  55, 165, CLAW_CLOSE_ANGLE}
};

#define MAXSPEED    (10)    // 舵机最大旋转速度
int demo_speed = 1;         // 1倍速、2倍速......


#define JOYSTICK_LEFT_BUTTON    (2)     // 左键用于学习模式
#define JOYSTICK_RIGHT_BUTTON   (4)     // 右键用于播放预设动作
#define JOYSTICK_LED            (3)     // 摇杆模块上面的LED灯，接入主板3号脚

bool has_btn_been_pressed = false;          // 记录上次的按键状态



void setup() {
  Serial.begin(115200);

  pinMode(JOYSTICK_LEFT_BUTTON, INPUT_PULLUP);      // 左键用于学习模式
  pinMode(JOYSTICK_RIGHT_BUTTON, INPUT_PULLUP);     // 右键用于播放预设动作

  pinMode(JOYSTICK_LED, OUTPUT);
  digitalWrite(JOYSTICK_LED, HIGH); // 亮灯

  Serial.println("System Running...");
  Serial.print(digitalRead(JOYSTICK_LEFT_BUTTON));      //读取并串口打印按键状态
  Serial.print(", ");
  Serial.println(digitalRead(JOYSTICK_RIGHT_BUTTON));   //读取并串口打印按键状态

  // 初始化工作
  initialization();

  if (0 == digitalRead(JOYSTICK_LEFT_BUTTON))
  {
    // 左键用于学习模式
    learning_mode = true;
    has_btn_been_pressed = true;  // 记录有按键按下了！
    learn_action_count = 0;
    delay(1000);
    digitalWrite(JOYSTICK_LED, LOW);    // 灭灯

    Serial.println("Enter learning_mode!!");    // 进入学习模式
  }
  else if (0 == digitalRead(JOYSTICK_RIGHT_BUTTON))
  {
    // 右键用于播放预设动作
    play_demo_mode = true;
    has_btn_been_pressed = true;  // 记录有按键按下了！
    Serial.println("Enter play_demo_mode!!");

    // 开始播放预设动作序列
    play_demo();
  }
  else
  {
    // 炫耀武力，爪子抓2次
    cut_cut();
    Serial.println("Enter JoyStick Control Mode!!");    // 进入摇杆操控模式
  }
}

void loop() {
  handle_serial();              // [OctoBot] remote serial command path (Sx:angle)
  move_by_joystick_contrl();
  learning_actions();
  report_angles();              // [OctoBot] send actual angles back to the Pi
}

void initialization() {
  servo_pins[0] = 11;           // pin 11 -- Servo base   底座舵机
  servo_min_angle[0] = 0;       // 允许舵机旋转到达的最小值
  servo_max_angle[0] = 180;     // 允许舵机旋转到达的最大值
  servo_init_angle[0] = 90;     // 刚上电时，舵机的初始角度

  servo_pins[1] = 10;           // 10 : Servo left   左臂舵机
  servo_min_angle[1] = 10;      // 允许舵机旋转到达的最小值
  servo_max_angle[1] = 140;     // 允许舵机旋转到达的最大值
  servo_init_angle[1] = 90;     // 刚上电时，舵机的初始角度

  servo_pins[2] = 9;            //  9 : Servo right  右臂舵机
  servo_min_angle[2] = 40;      // 允许舵机旋转到达的最小值
  servo_max_angle[2] = 170;     // 允许舵机旋转到达的最大值
  servo_init_angle[2] = 90;     // 刚上电时，舵机的初始角度

  servo_pins[3] = 5;                        //  5 : Servo claw   爪子舵机
  servo_min_angle[3] = CLAW_CLOSE_ANGLE;    // 允许舵机旋转到达的最小值
  servo_max_angle[3] = CLAW_OPEN_ANGLE;     // 允许舵机旋转到达的最大值
  servo_init_angle[3] = CLAW_OPEN_ANGLE;   // 刚上电时，舵机的初始角度

  // 学习模式清空所有动作
  for (int i = 0 ; i < LEARN_MAX_ACTIONS; i++) {
    for (int j = 0 ; j < SERVOS; j++) {
      learn_actions[i][j] = 0;
    }
  }

  // 给所有舵机设置初始角度
  init_servos();
}


void init_servos() {
  for (int i = 0; i < SERVOS; i++)
  {
    arm_servos[i].attach(servo_pins[i], 500, 2500);      // 把舵机关联到对应的PWM引脚上
    arm_servos[i].write(servo_init_angle[i]); // 写入舵机的初始角度
    joystick_value[i] = 0;                    // 摇杆ADC值初始化为0
  }
}


// 炫耀武力，爪子抓2次
void cut_cut() {
  delay(1000);
  for (int i = 0; i < 2; i++)
  {
    close_claw(true);
    delay(150);
    close_claw(false);
    delay(150);
  }
}

// 控制爪子开闭
void close_claw(bool close)
{
  if (close) {
    arm_servos[CLAW_SERVO_INDEX].write(CLAW_CLOSE_ANGLE);
  } else {
    arm_servos[CLAW_SERVO_INDEX].write(CLAW_OPEN_ANGLE);
  }
}

void move_by_joystick_contrl()
{
  bool joy_changed = false;

  for (int i = 0; i < SERVOS; i++)
  {
    // 读取摇杆ADC值
    // A0 --> joystick_value[0] --> 左摇杆左右推，控制底座舵机旋转；
    // A1 --> joystick_value[1] --> 左摇杆前后推，控制左臂舵机旋转；
    // A2 --> joystick_value[2] --> 右摇杆前后推，控制右臂舵机旋转；
    // A3 --> joystick_value[3] --> 右摇杆左右推，控制爪子舵机旋转；
    joystick_value[i] = analogRead(i);

#if 1
    // 串口打印摇杆ADC值
    Serial.print("A[");
    Serial.print(i);
    Serial.print("]=");
    Serial.print(joystick_value[i]);
    Serial.print(", ");
#endif

    // 读取舵机当前的旋转角度
    servo_cur_angle[i] = arm_servos[i].read();

    if (joystick_value[i] > JOYSTICK_MAX_THRESH)    // 摇杆ADC值超过最大阈值
    {
      joy_changed = true;    // 摇杆被推动过了！

      if (servo_cur_angle[i] > servo_min_angle[i])
      {
        // 如果舵机当前角度，大于，允许舵机旋转到达的最小值，则舵机角度降低1度
        --servo_cur_angle[i];
      }

      if (i == CLAW_SERVO_INDEX)
      {
        // 如果是爪子舵机，则直接闭合爪子
        servo_cur_angle[i] = CLAW_OPEN_ANGLE;
      }
    }
    else if (joystick_value[i] < JOYSTICK_MIN_THRESH)   // 摇杆ADC值小于最小阈值
    {
      joy_changed = true;   // 摇杆被推动过了！

      if (servo_cur_angle[i] < servo_max_angle[i])
      {
        // 如果舵机当前角度，小于，允许舵机旋转到达的最大值，则舵机角度增加1度
        ++servo_cur_angle[i];
      }

      if (i == CLAW_SERVO_INDEX)
      {
        // 如果是爪子舵机，则直接打开爪子
        servo_cur_angle[i] = CLAW_CLOSE_ANGLE;
      }
    }
  }
  Serial.println("");

  if (true == joy_changed)
  {
    // 只要摇杆被推动过了，就刷新一遍舵机角度: 将当前最新的舵机角度值，写入舵机
    for (int i = 0 ; i < SERVOS; i++)
    {
#if 1
      // 串口打印舵机角度
      Serial.print("servo[");
      Serial.print(i);
      Serial.print("]=");
      Serial.print(servo_cur_angle[i]);
      Serial.print(", ");
#endif
      arm_servos[i].write(servo_cur_angle[i]);
    }
    Serial.println("");
  }

  delay(20);
}


/*
    机械臂动作学习模式操作步骤：
    1、按住遥杆左键，再按一下arduino重启按钮或者关机重启，遥杆板指示灯灭说明加入录制状态；
    2、通过遥杆控制机械臂状态，到达指定位置，按一下遥杆左键，记录当前状态，依次操作；
    3、按一下遥杆右键，结束录制，机械臂自动循环地执行之前记录学习的动作；
    4、再次按遥杆左键，停止自动循环，进入摇杆操控模式。
    注意：所记录的动作重启或关机后会消失，重新录制会覆盖之前的动作。
*/
void learning_actions() {
  if (false == repeat_mode)
  {
    if (true == learning_mode) // 进入学习模式
    {

      if (0 == digitalRead(JOYSTICK_RIGHT_BUTTON))
      {
        // 按一下遥杆右键，结束学习模式，机械臂开始自动循环地执行之前记录学习的动作
        repeat_mode = true;
        return;
      }

      // 左键按下
      bool btn_pressed = (0 == digitalRead(JOYSTICK_LEFT_BUTTON));

      if ((false == has_btn_been_pressed) && (true == btn_pressed))
      {
        // 如果上次没有按键按下，现在左键按下了，说明要记录一次机械臂动作状态
        if (learn_action_count < LEARN_MAX_ACTIONS)
        {
          // 如果动作次数，还没有超过最大值，就要记录
          Serial.print("learn_action_count = ");
          Serial.println(learn_action_count);
          for (int i = 0; i < SERVOS; i++)
          {
            int tmp = arm_servos[i].read(); // 读取舵机的当前角度值
            //Serial.print(tmp);
            //Serial.print(" , ");
            learn_actions[learn_action_count][i] = tmp; // 存储舵机的当前角度值
          }
          Serial.println("");

          learn_action_count++; // 动作次数+1
        }
        else
        {
          // 如果动作次数，达到最大值，就强制结束学习模式，机械臂开始自动循环地执行之前记录学习的动作
          repeat_mode = true;
        }
      }

      // 将当前按键状态，记录为"上次按键的状态"
      has_btn_been_pressed = btn_pressed;
    }
  }
  else
  {
    // 机械臂开始自动循环地执行之前记录学习的动作
    play_learned_actions();
  }
}


void play_learned_actions()
{
  digitalWrite(JOYSTICK_LED, HIGH); // 亮灯

  // learn_action_count: 0 -- learn_action_count-1
  Serial.print("play_learned_actions: total actions=");
  Serial.println(learn_action_count);

  Serial.print("moving speed = ");
  Serial.println(demo_speed);

  // 机械臂从学习模式记录的最后动作状态，回到第一个动作状态
  move_from_to(learn_actions[learn_action_count - 1], learn_actions[0]);

  while (1)
  {
    for (int i = 0; i < learn_action_count - 1; i++)
    {
      // 摇杆左右键，任何按键按下，结束学习模式
      if (is_btn_pressed())
      {
        learning_mode = false;
        repeat_mode = false;
        play_demo_mode = false;
        return;
      }
      // 机械臂从当前动作，运动、转移至下一个动作
      move_from_to(learn_actions[i], learn_actions[i + 1]);
    }
    delay(500 / demo_speed);

    // 机械臂从学习模式记录的最后动作状态，回到第一个动作状态
    move_from_to(learn_actions[learn_action_count - 1], learn_actions[0]);
    delay(500 / demo_speed);
  }
}

/*
    move_from_to:
    目的是，让机械臂的2个动作之间的变化、运动、转移，更加平滑，
    不要让舵机瞬间完成角度切换，一方面增加舵机使用寿命，一方面机械臂工作更加自然。
*/
void move_from_to(int *action_from, int *action_to)
{
  int max_angle = 0;
  int max_steps = 0;
  float step_angle[SERVOS];

  // 调整机械臂的运动、转移速度
  adjust_speed();

  /*
    1. 找到角度变化最大的那个舵机，算出角度变化绝对值max_angle；
    2. 角度变化值max_angle ÷ 舵机旋转速度demo_speed，就是舵机要运行的步数max_steps；
    3. 根据总步数max_steps，计算出每个舵机单步转动的角度step_angle；
  */
  max_angle = max(max(abs(action_to[0] - action_from[0]), abs(action_to[1] - action_from[1])), abs(action_to[2] - action_from[2]));
  max_steps = max_angle / demo_speed;
  max_steps = max_steps < 1 ? 1 : max_steps;
  for (int i = 0; i < CLAW_SERVO_INDEX; i++)
  {
    step_angle[i] = float(action_to[i] - action_from[i]) / float(max_steps);
  }

  for (int j = 1; j <= max_steps; j++) // 步数j累加
  {
    for (int i = 0; i < CLAW_SERVO_INDEX; i++)
    {
      // 随着j慢慢增大，new_angle 会慢慢趋近于 action_to[i]，也就实现了运动平滑的效果
      int new_angle = action_from[i] + j * step_angle[i];

      if ((new_angle < servo_min_angle[i]) || (new_angle > servo_max_angle[i]))
      {
        // 舵机角度值超出范围，忽略
        continue;
      }

      arm_servos[i].write(new_angle);  // 将最新的角度值，写入舵机
    }
    delay(20);
  }

  // 爪子舵机的开闭动作，不需要平滑过渡，直接设置角度给舵机
  arm_servos[CLAW_SERVO_INDEX].write(action_to[CLAW_SERVO_INDEX]);
  delay(20);

}

// 播放预设动作序列
void play_demo()
{
  // 计算总共有多少个动作？
  int counts = sizeof(demo_actions) / (SERVOS * sizeof(int));

  Serial.print("demo_actions counts = ");
  Serial.println(counts);

  move_from_to(servo_init_angle, demo_actions[0]);

  while (1)
  {
    for (int i = 0; i < counts - 1; i++)
    {
      // 摇杆左右键，任何按键按下，结束播放预设动作序列
      if (is_btn_pressed())
      {
        learning_mode = false;
        repeat_mode = false;
        play_demo_mode = false;
        return;
      }

      // 机械臂从当前动作，运动、转移至下一个动作
      move_from_to(demo_actions[i], demo_actions[i + 1]);
    }
  }
}


// 调整机械臂的运动、转移速度
void adjust_speed()
{
  // 任何一个摇杆推动任何一个方向，都可以调整速度
  for (int i = 0; i < SERVOS; i++)
  {
    if (analogRead(i) > JOYSTICK_MAX_THRESH) demo_speed++; // 速度加

    if (analogRead(i) < JOYSTICK_MIN_THRESH) demo_speed--; // 速度减
  }
  demo_speed = demo_speed < 1 ? 1 : demo_speed;
  demo_speed = demo_speed > MAXSPEED ? MAXSPEED : demo_speed;
}

bool is_btn_pressed()
{

  if ((false == has_btn_been_pressed) && ((0 == digitalRead(JOYSTICK_RIGHT_BUTTON)) || (0 == digitalRead(JOYSTICK_LEFT_BUTTON))))
  {
    // 如果上次没有按键按下，而现在左键或者右键按下了，则认为现在确实有按键按下了
    has_btn_been_pressed = true;
    return true;
  }
  else if ((1 == digitalRead(JOYSTICK_RIGHT_BUTTON)) && (1 == digitalRead(JOYSTICK_LEFT_BUTTON)))
  {
    // 如果左右键都没有按下，则认为确实没有按键按下
    has_btn_been_pressed = false;
  }
  return false;
}


// === [OctoBot] remote serial control (added v1.71 -> v1.80) =================
// Newline-terminated ASCII command parser. Keeps the local joystick loop intact
// as a manual fallback; the OpenWRT serial bus drives the arm remotely.
//   Sx:angle  set servo x (0..3) to angle, clamped to servo_min/max_angle
//   DEMO LEARN PLAY STOP   teach-and-repeat modes
//   SPD:n     playback speed 1..MAXSPEED
void process_command(String cmd) {
  cmd.trim();
  if (cmd.startsWith("S") && cmd.indexOf(':') == 2) {
    int servo = cmd.charAt(1) - '0';
    int angle = cmd.substring(3).toInt();
    if (servo >= 0 && servo < SERVOS &&
        angle >= servo_min_angle[servo] && angle <= servo_max_angle[servo]) {
      arm_servos[servo].write(angle);
      servo_cur_angle[servo] = angle;
      Serial.print("OK S"); Serial.print(servo); Serial.print(":"); Serial.println(angle);
    } else {
      Serial.println("ERR RANGE");
    }
  } else if (cmd == "DEMO") {
    play_demo_mode = true; play_demo(); play_demo_mode = false;
  } else if (cmd == "LEARN") {
    learning_mode = true; learn_action_count = 0;
  } else if (cmd == "PLAY") {
    repeat_mode = true; play_learned_actions();
  } else if (cmd == "STOP") {
    learning_mode = false; repeat_mode = false; play_demo_mode = false;
  } else if (cmd.startsWith("SPD:")) {
    demo_speed = constrain(cmd.substring(4).toInt(), 1, MAXSPEED);
  } else if (cmd.length() > 0) {
    Serial.println("ERR UNKNOWN");
  }
}

void handle_serial() {
  static String line;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n') { process_command(line); line = ""; }
    else if (c != '\r') { line += c; }
  }
}

// [OctoBot] send actual servo angles back to the Pi so the cloud UI can display them.
// Output format: ANG:base,left,right,claw\n
void report_angles() {
  unsigned long now = millis();
  if (now - last_angle_report < ANGLE_REPORT_MS) return;
  last_angle_report = now;

  Serial.print("ANG:");
  for (int i = 0; i < SERVOS; i++) {
    Serial.print(servo_cur_angle[i]);
    if (i < SERVOS - 1) Serial.print(",");
  }
  Serial.println("");
}
